"""Run the identical real-cluster Molecule scenario for every supported adapter."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def main():
    versions = json.loads((HERE / 'matrix.json').read_text())
    native_platform = 'linux/' + subprocess.check_output(['docker', 'version', '--format', '{{.Server.Arch}}'], text=True).strip()
    selected = sys.argv[1:] or ['4.1', '4.0', '5.0', '3.11', '3.0', '2.2']
    reports = HERE / '.state' / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    summary_file = reports / 'summary.json'
    summary = json.loads(summary_file.read_text()) if summary_file.exists() else {}
    git = ['git', '-c', f'safe.directory={ROOT}', '-C', str(ROOT)]
    source_commit = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip()
    source_dirty = bool(subprocess.check_output([*git, 'status', '--porcelain'], text=True).strip())
    run_id = uuid.uuid4().hex
    for module in selected:
        config = versions[module]
        version = config['version']
        jar = ROOT / f'cassandra-{module}/target/cassandra-ldap-{version}-{config["plugin_version"]}.jar'
        if not jar.is_file():
            raise RuntimeError(f'Missing plugin artifact: {jar}')
        env = dict(os.environ, CASSANDRA_IMAGE=config.get('image', f'cassandra:{version}'),
                   CASSANDRA_PLATFORM=native_platform, LDAP_PLUGIN_JAR=str(jar),
                   LDAP_AUTHENTICATOR=config['authenticator'], CASSANDRA_VERSION=version)
        directory = reports / version
        directory.mkdir(exist_ok=True)
        report = HERE / '.state' / f'{version}-results.xml'
        server_versions = HERE / '.state' / 'server-versions.json'
        server_versions.unlink(missing_ok=True)
        if report.exists():
            report.rename(directory / 'previous-results.xml')
        (directory / 'results.xml').unlink(missing_ok=True)
        print(f'=== Cassandra {version}: two nodes + LDAP ===', flush=True)
        jar_hash = hashlib.sha256(jar.read_bytes()).hexdigest()
        start = time.monotonic()
        started_at = time.time()
        with (directory / 'molecule.log').open('w') as output:
            run = subprocess.run(['molecule', 'test', '-s', 'integration'], cwd=ROOT,
                                 env=env, stdout=output, stderr=subprocess.STDOUT)
        result = {'exit_code': run.returncode, 'elapsed_seconds': round(time.monotonic() - start, 1),
                  'jar_sha256': jar_hash, 'image': env['CASSANDRA_IMAGE'],
                  'platform': native_platform, 'run_id': run_id, 'source_commit': source_commit,
                  'source_dirty': source_dirty, 'started_at': started_at}
        if server_versions.exists():
            result['server_versions'] = json.loads(server_versions.read_text())
        if hashlib.sha256(jar.read_bytes()).hexdigest() != jar_hash:
            result['artifact_changed_during_test'] = True
            result['exit_code'] = 1
        if report.exists():
            (directory / 'results.xml').write_bytes(report.read_bytes())
            suites = list(ET.parse(report).getroot().iter('testsuite'))
            for field in ['tests', 'failures', 'errors', 'skipped']:
                result[field] = sum(int(suite.attrib.get(field, 0)) for suite in suites)
        cluster_log = HERE / '.state' / f'{version}-containers.log'
        if cluster_log.exists():
            (directory / 'containers.log').write_bytes(cluster_log.read_bytes())
        lifecycle = (directory / 'molecule.log').read_text()
        result['idempotence_passed'] = 'idempotence: Executed: Successful' in lifecycle
        result['teardown_passed'] = 'destroy: Executed: Successful' in lifecycle
        if (result.get('tests') != 15 or any(result.get(field, -1) != 0 for field in ('failures', 'errors', 'skipped'))
                or result.get('server_versions') != {'cassandra1': version, 'cassandra2': version}
                or not result['idempotence_passed'] or not result['teardown_passed']):
            result['exit_code'] = result['exit_code'] or 1
        summary[version] = result
        (directory / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        summary_file.write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({version: result}), flush=True)
    return int(any(summary[versions[module]['version']]['exit_code'] or summary[versions[module]['version']].get('tests', 0) != 15
                   or summary[versions[module]['version']].get('skipped', 0) for module in selected))


if __name__ == '__main__':
    sys.exit(main())
