"""Package clean tagged sources, checked shaded jars and fast-test evidence."""
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = {'2.2', '3.0', '3.11', '4.0', '4.1', '5.0'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(root, *args):
    return subprocess.check_output(['git', '-c', f'safe.directory={root}', '-C', str(root), *args], text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def counters(path, expected):
    tree = ET.parse(path).getroot()
    result = {key: sum(int(suite.attrib.get(key, 0)) for suite in tree.iter('testsuite'))
              for key in ('tests', 'failures', 'errors', 'skipped')}
    require(result == {'tests': expected, 'failures': 0, 'errors': 0, 'skipped': 0},
            f'Failed, skipped or incomplete test report: {path.name}')
    require(len(list(tree.iter('testcase'))) == expected
            and not any(list(tree.iter(tag)) for tag in ('failure', 'error', 'skipped')),
            f'Inconsistent test cases: {path.name}')
    return result


def checksums(files):
    return ''.join(f'{digest(data)}  {name}\n' for name, data in sorted(files.items())).encode()


def repository_slug(root, supplied):
    if supplied:
        slug = supplied
    else:
        remote = git(root, 'remote', 'get-url', 'origin')
        slug = re.sub(r'^(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)', '', remote).removesuffix('.git')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', slug), 'Expected a GitHub owner/repository')
    return slug


def release_changes(root, version):
    changelog = (root / 'CHANGELOG.md').read_text()
    headings = list(re.finditer(r'^## (\d+\.\d+\.\d+) - (\d{4}-\d{2}-\d{2})[ \t]*$', changelog, re.M))
    matching = [heading for heading in headings if heading.group(1) == version]
    require(len(matching) == 1, 'Changelog must contain exactly one dated entry for the release version')
    heading = matching[0]
    datetime.strptime(heading.group(2), '%Y-%m-%d')
    following = re.search(r'^## ', changelog[heading.end():], re.M)
    end = heading.end() + following.start() if following else len(changelog)
    section = changelog[heading.end():end].strip()
    require(re.search(r'^- \S', section, re.M), 'Changelog release entry must contain changes')
    return section


def prepare_release(root, tag, repository=None):
    root = pathlib.Path(root).resolve()
    require(re.fullmatch(r'v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)', tag), 'Expected a stable vMAJOR.MINOR.PATCH tag')
    version = tag[1:]
    ns = '{http://maven.apache.org/POM/4.0.0}'
    require(ET.parse(root / 'pom.xml').getroot().findtext(ns + 'version') == version,
            'Tag and Maven release version differ')
    commit = git(root, 'rev-parse', 'HEAD')
    require(git(root, 'rev-parse', f'refs/tags/{tag}^{{commit}}') == commit, 'Release tag must point to HEAD')
    require(not git(root, 'status', '--porcelain'), 'Release source tree must be clean')
    slug = repository_slug(root, repository)
    target = root / 'dist' / tag
    require(not target.exists(), 'Release output already exists; do not overwrite a prepared release')
    changes = release_changes(root, version)

    scenario = root / 'molecule/integration'
    matrix = json.loads((scenario / 'matrix.json').read_text())
    require(set(matrix) == MODULES, 'A release requires all six Cassandra adapters')
    files, artifacts, jars = {}, [], []
    for module, config in matrix.items():
        server = config['version']
        require(config['plugin_version'] == version, 'Adapter artifact versions must match the release')
        filename = f'cassandra-ldap-{server}-{version}.jar'
        jar = root / f'cassandra-{module}' / 'target' / filename
        data = jar.read_bytes()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = set(archive.namelist())
            require({'com/instaclustr/cassandra/ldap/auth/LdapAccessSync.class',
                     'com/instaclustr/cassandra/ldap/conf/LdapSecretResolver.class',
                     'org/apache/cassandra/auth/LDAPCassandraRoleManager.class'} <= entries,
                    f'{server}: artifact is not the shaded plugin')
            require(not any(name.startswith(('org/yaml/snakeyaml/', 'com/google/common/', 'org/apache/cassandra/cql3/')) for name in entries),
                    f'{server}: artifact bundles a server dependency')
            properties = archive.read(f'META-INF/maven/com.instaclustr/cassandra-ldap-{server}/pom.properties').decode()
            require(re.search(rf'^version={re.escape(version)}\s*$', properties, re.M), f'{server}: embedded Maven version differs')
        files[filename] = data
        jars.append(jar)
        artifacts.append({'module': module, 'cassandra_version': server, 'filename': filename,
                          'sha256': digest(data), 'size_bytes': len(data)})

    unit_report = root / 'cassandra-4.1/target/surefire-reports/TEST-TestSuite.xml'
    unit = counters(unit_report, 18)
    require(max(jar.stat().st_mtime for jar in jars) <= unit_report.stat().st_mtime,
            'Unit report must be produced after packaging jars')
    manifest = {'schema_version': 2, 'version': version, 'tag': tag, 'commit': commit, 'repository': slug,
                'verification': {'java_unit_tests': unit,
                                 'cluster_e2e': {'status': 'not_run_by_release_pipeline', 'execution': 'local_only'}},
                'artifacts': artifacts}
    files['release-manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    base = f'https://github.com/{slug}'
    download = f'{base}/releases/download/{tag}'
    bundle_name = f'cassandra-ldap-{version}.zip'
    def source_links(text):
        return re.sub(r'\]\(([^)]+)\)',
                      lambda match: match.group(0) if re.match(r'^(?:[a-z]+:|#)', match[1])
                      else f']({base}/blob/{tag}/{match[1]})', text)
    notes = f'''# Cassandra LDAP Authenticator {tag}

{source_links(changes)}

## Downloads

[Complete bundle]({download}/{bundle_name}) or one matching jar from Assets below.
[SHA256SUMS]({download}/SHA256SUMS) and [manifest]({download}/release-manifest.json).

## Verification

CI: 18 Java unit tests, packaging/docs checks and six adapter builds. CI does not start Cassandra,
LDAP or systemd clusters; local E2E is separate, not verification of these CI-built bytes.
Source: [`{commit[:12]}`]({base}/commit/{commit}).

[Installation]({base}/blob/{tag}/README.adoc) |
[Operations and limits]({base}/blob/{tag}/ACCESS_SYNC.md) |
[Test scope]({base}/blob/{tag}/molecule/integration/README.md) |
[Full changelog]({base}/blob/{tag}/CHANGELOG.md)
'''
    install = f'''# Installing Cassandra LDAP {tag}

1. Select one jar for the exact Cassandra release. Do not install all six jars.
2. Verify SHA256SUMS before deployment. Keep a working native administrator.
3. Provision system_auth and ldap_auth with suitable NetworkTopologyStrategy
   replication, repair after replication changes, and apply conf/access-sync-schema.cql.
4. Create mapped roles and keyspaces. LDAP users must not be able to write ldap_auth.
5. Configure exactly one bind-secret source in conf/ldap.yaml. Prefer systemd
   LoadCredentialEncrypted; see SECRET_HANDLING.md. Restrict file permissions and
   set -Dcassandra.ldap.config.file=/etc/cassandra/ldap.yaml in node JVM options.
6. Configure the correct authenticator, LDAPCassandraRoleManager and CassandraAuthorizer.
   Configure QUORUM auth writes on 4.1/5.0. Roll and verify nodes one at a time.

The LDAP bind identity is not given a Cassandra role or SUPERUSER automatically.
Existing roles are unchanged: review unnecessary bind-DN privileges explicitly
while preserving an independent administrator. See the access review in ACCESS_SYNC.md
on the source site below. The example password is a placeholder, not a credential.
Use client TLS and LDAPS with trusted certificates. Never use public test passwords.

Full installation: {base}/blob/{tag}/README.adoc
Operations and recovery: {base}/blob/{tag}/ACCESS_SYNC.md
Verification scope: {base}/blob/{tag}/molecule/integration/README.md
'''
    secret_guide = (root / 'SECRET_HANDLING.md').read_text().replace(
        '](molecule/integration/README.md)', f']({base}/blob/{tag}/molecule/integration/README.md)')
    secret_guide = secret_guide.replace('](ACCESS_SYNC.md#planned-maintenance)',
                                      f']({base}/blob/{tag}/ACCESS_SYNC.md#planned-maintenance)')
    payload = {**files, 'conf/ldap.yaml': (root / 'conf/ldap.yaml').read_bytes(),
               'SECRET_HANDLING.md': secret_guide.encode(),
               'CHANGELOG.md': source_links((root / 'CHANGELOG.md').read_text()).encode(),
               'conf/access-sync-schema.cql': (root / 'conf/access-sync-schema.cql').read_bytes(),
               'LICENSE': (root / 'LICENSE').read_bytes(), 'INSTALL.md': install.encode()}
    payload['SHA256SUMS'] = checksums(payload)
    stamp = datetime.fromtimestamp(max(315532800, int(git(root, 'show', '-s', '--format=%ct', 'HEAD'))), timezone.utc)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(payload.items()):
            entry = zipfile.ZipInfo(f'cassandra-ldap-{version}/{name}', stamp.timetuple()[:6])
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED)
    files[bundle_name] = stream.getvalue()
    files['SHA256SUMS'] = checksums(files)
    files['RELEASE_NOTES.md'] = notes.encode()
    if not target.parent.exists():
        target.parent.mkdir(parents=True)
        target.parent.chmod(0o755)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix='.package-') as staging:
        for name, data in files.items():
            path = pathlib.Path(staging) / name
            path.write_bytes(data)
            path.chmod(0o644)
        # Docker builds run as root; host-side artifact upload runs as the runner user.
        pathlib.Path(staging).chmod(0o755)
        pathlib.Path(staging).rename(target)
    return target


def main():
    tag = os.environ.get('RELEASE_TAG') or git(ROOT, 'describe', '--tags', '--exact-match', 'HEAD')
    target = prepare_release(ROOT, tag, os.environ.get('GITHUB_REPOSITORY'))
    print(f'Prepared {tag}: six checked jars, bundle, manifest and checksums in dist/{target.name}')


if __name__ == '__main__':
    main()
