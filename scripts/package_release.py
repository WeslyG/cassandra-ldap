"""Package only clean, tagged sources and jars verified by one full cluster run."""
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

    scenario = root / 'molecule/integration'
    matrix = json.loads((scenario / 'matrix.json').read_text())
    require(set(matrix) == MODULES, 'A release requires all six Cassandra adapters')
    reports = scenario / '.state/reports'
    summary = json.loads((reports / 'summary.json').read_text())
    run_ids = set()
    files, artifacts, jars, starts = {}, [], [], []
    for module, config in matrix.items():
        server = config['version']
        require(config['plugin_version'] == version, 'Adapter artifact versions must match the release')
        result = summary[server]
        require(result['source_commit'] == commit and result['source_dirty'] is False,
                f'{server}: e2e evidence is not from this clean commit')
        require(result['exit_code'] == 0 and result['tests'] == 15
                and all(result[key] == 0 for key in ('failures', 'errors', 'skipped')),
                f'{server}: e2e must pass 15/15 with no skips')
        require(result['idempotence_passed'] is True and result['teardown_passed'] is True,
                f'{server}: incomplete Molecule lifecycle')
        require(result['server_versions'] == {'cassandra1': server, 'cassandra2': server},
                f'{server}: actual node versions differ')
        require(result['image'] == config.get('image', f'cassandra:{server}'), f'{server}: unexpected server image')
        require(result['platform'] in ('linux/amd64', 'linux/arm64'), f'{server}: missing runtime platform')
        require(re.fullmatch(r'[a-f0-9]{32}', result['run_id']), f'{server}: invalid run identifier')
        run_ids.add(result['run_id'])
        starts.append(result['started_at'])
        counters(reports / server / 'results.xml', 15)
        lifecycle = (reports / server / 'molecule.log').read_text()
        require(all(marker in lifecycle for marker in ('idempotence: Executed: Successful', 'destroy: Executed: Successful')),
                f'{server}: lifecycle evidence missing')
        filename = f'cassandra-ldap-{server}-{version}.jar'
        jar = root / f'cassandra-{module}' / 'target' / filename
        data = jar.read_bytes()
        require(digest(data) == result['jar_sha256'], f'{server}: jar differs from the tested artifact')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = set(archive.namelist())
            require({'com/instaclustr/cassandra/ldap/auth/LdapAccessSync.class',
                     'org/apache/cassandra/auth/LDAPCassandraRoleManager.class'} <= entries,
                    f'{server}: artifact is not the shaded plugin')
            require(not any(name.startswith(('org/yaml/snakeyaml/', 'com/google/common/', 'org/apache/cassandra/cql3/')) for name in entries),
                    f'{server}: artifact bundles a server dependency')
            properties = archive.read(f'META-INF/maven/com.instaclustr/cassandra-ldap-{server}/pom.properties').decode()
            require(re.search(rf'^version={re.escape(version)}\s*$', properties, re.M), f'{server}: embedded Maven version differs')
        files[filename] = data
        jars.append(jar)
        artifacts.append({'module': module, 'cassandra_version': server, 'filename': filename,
                          'sha256': digest(data), 'size_bytes': len(data), 'e2e_tests': 15,
                          'server_image': result['image'], 'platform': result['platform'],
                          'nodes': result['server_versions'], 'idempotence': True, 'teardown': True})

    require(len(run_ids) == 1, 'Mixed e2e runs cannot be used for a release; run the full matrix')
    unit_report = root / 'cassandra-4.1/target/surefire-reports/TEST-TestSuite.xml'
    unit = counters(unit_report, 10)
    require(max(jar.stat().st_mtime for jar in jars) <= unit_report.stat().st_mtime <= min(starts),
            'Unit report must be produced after packaging jars and before the full matrix')
    manifest = {'schema_version': 1, 'version': version, 'tag': tag, 'commit': commit, 'repository': slug,
                'verification': {'java_unit_tests': unit, 'e2e_tests': 90, 'e2e_run_id': next(iter(run_ids)),
                                 'topology': 'two Cassandra nodes and OpenLDAP per adapter'},
                'artifacts': artifacts}
    files['release-manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    base = f'https://github.com/{slug}'
    download = f'{base}/releases/download/{tag}'
    table = '\n'.join(f'| {item["cassandra_version"]} | [{item["filename"]}]({download}/{item["filename"]}) | 15/15 |' for item in artifacts)
    bundle_name = f'cassandra-ldap-{version}.zip'
    notes = f'''# Cassandra LDAP Authenticator {tag}

LDAP authentication and managed access synchronization for **Cassandra 2.2 through 5.0**.

## Downloads

Choose **one jar matching your Cassandra release**, or download the
[complete bundle]({download}/{bundle_name}) with all adapters, configuration,
journal schema, license and installation instructions.

| Cassandra | Plugin jar | Cluster e2e |
|---|---|---:|
{table}

[SHA256SUMS]({download}/SHA256SUMS) verifies every downloadable artifact.
[release-manifest.json]({download}/release-manifest.json) records the source commit,
tested jar hashes, server images, node versions and test run identifier.

## Access Model

- Flat LDAP connection settings and structured YAML group mappings.
- Union of direct LDAP groups into Cassandra role memberships and keyspace permissions.
- Managed GRANT/REVOKE synchronization with a write-ahead ownership journal.
- Preservation of unrelated manual grants and background reconciliation.
- Fresh LDAP credential verification, escaped LDAP/CQL values and fail-closed synchronization.
- Native administrator access for recovery when LDAP is unavailable.

## Verified Build

**10 Java unit tests and 90 cluster e2e checks passed, with no skips.** Each adapter
ran against two Cassandra nodes and OpenLDAP, including idempotence, concurrent
logins, existing-session revocation, group/configuration changes, manual-grant
preservation, directory/replica outages, policy mismatch and lock recovery.
Source: [`{commit[:12]}`]({base}/commit/{commit}).

## Installation and Safety

Provision `ldap_auth` using the supplied schema, create mapped roles/keyspaces,
install only the matching shaded jar, render `ldap.yaml` with your own secret,
and roll nodes with native administrator access available.

Read the [installation guide]({base}/blob/{tag}/README.adoc),
[operations guide]({base}/blob/{tag}/ACCESS_SYNC.md) and
[test scope]({base}/blob/{tag}/molecule/integration/README.md) before deployment.

**Operational limits:** revocation is subject to reconciliation/cache delays;
the global lock has no TTL and requires deliberate recovery after an abandoned
owner. The bind-DN Cassandra role is created as SUPERUSER. Disabled AD accounts
need operator revocation for existing grants. Nested/primary AD groups are not
expanded. OpenLDAP e2e is not validation of AD, LDAPS, multi-DC or production load.

The 2.2 test image uses exact Cassandra 2.2.19 server binaries with native Java 8
and JNA 4.2.2. Compatibility is established for the exact server releases above,
not every patch release or upstream security support status.
'''
    install = f'''# Installing Cassandra LDAP {tag}

1. Select one jar for the exact Cassandra release. Do not install all six jars.
2. Verify SHA256SUMS before deployment. Keep a working native administrator.
3. Provision system_auth and ldap_auth with suitable NetworkTopologyStrategy
   replication, repair after replication changes, and apply conf/access-sync-schema.cql.
4. Create mapped roles and keyspaces. LDAP users must not be able to write ldap_auth.
5. Render conf/ldap.yaml with deployment secrets, restrict file permissions, and
   set -Dcassandra.ldap.config.file=/etc/cassandra/ldap.yaml in node JVM options.
6. Configure the correct authenticator, LDAPCassandraRoleManager and CassandraAuthorizer.
   Configure QUORUM auth writes on 4.1/5.0. Roll and verify nodes one at a time.

The bind-DN Cassandra role is created as SUPERUSER. Review this security behavior
before enabling LDAP logins. The example password is a placeholder, not a credential.
Use client TLS and LDAPS with trusted certificates. Never use public test passwords.

Full installation: {base}/blob/{tag}/README.adoc
Operations and recovery: {base}/blob/{tag}/ACCESS_SYNC.md
Verification scope: {base}/blob/{tag}/molecule/integration/README.md
'''
    payload = {**files, 'conf/ldap.yaml': (root / 'conf/ldap.yaml').read_bytes(),
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
    print(f'Prepared {tag}: six tested jars, bundle, manifest and checksums in dist/{target.name}')


if __name__ == '__main__':
    main()
