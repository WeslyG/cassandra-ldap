"""Local-only privilege experiment; never changes production sources or artifacts."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import time
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUTPUT = HERE / '.state' / 'superuser-experiment'


def run_case(module, variant, config, platform):
    directory = OUTPUT / 'reports' / module / variant
    directory.mkdir(parents=True, exist_ok=True)
    for name in ('privilege.xml', 'access.xml', 'dba.xml', 'dba-evidence.json'):
        (directory / name).unlink(missing_ok=True)
    (HERE / '.state/server-versions.json').unlink(missing_ok=True)
    artifact = 'baseline' if variant == 'demoted' else variant
    jar = OUTPUT / 'artifacts' / artifact / f'cassandra-{module}.jar'
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    inputs = ['harness.py', 'test_superuser.py', 'test_superuser_dba.py', 'test_access.py',
              'superuser.ldif', 'ldap.ldif', 'ldap.yaml']
    test_hashes = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in inputs}
    env = dict(os.environ, CASSANDRA_VERSION=config['version'],
               CASSANDRA_IMAGE=config.get('image', 'cassandra:' + config['version']),
               CASSANDRA_PLATFORM=platform, LDAP_AUTHENTICATOR=config['authenticator'],
               LDAP_PLUGIN_JAR=str(jar), LDAP_SUPERUSER_EXPERIMENT=variant)
    if env.get('LDAP_TEST_SYSTEMD') == 'true':
        image = 'ldap-integration-systemd:' + config['version']
        subprocess.run(['docker', 'build', '-t', image, '--build-arg',
                        'CASSANDRA_SOURCE=' + env['CASSANDRA_IMAGE'], '-f',
                        str(HERE / 'Dockerfile.systemd'), str(HERE)], check=True)
        env.update(CASSANDRA_IMAGE=image, LDAP_STOP_SIGNAL='SIGRTMIN+3')
    result = {'module': module, 'variant': variant, 'jar_sha256': digest,
              'source_commit': (OUTPUT / 'source-commit.txt').read_text().strip(),
              'started_at': time.time(), 'systemd': env.get('LDAP_TEST_SYSTEMD') == 'true', 'exit_code': 1,
              'test_input_sha256': test_hashes}
    print(f'=== SUPERUSER experiment: Cassandra {module}, {variant} ===', flush=True)
    start = time.monotonic()
    with (directory / 'run.log').open('w') as log:
        def command(*args, check=True):
            return subprocess.run(args, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                  check=check, timeout=1800)
        try:
            command('molecule', 'destroy', '-s', 'integration')
            command('molecule', 'converge', '-s', 'integration')
            command('molecule', 'idempotence', '-s', 'integration')
            command('python3', '-m', 'pytest', '-v', '-s', str(HERE / 'test_superuser.py'),
                    '--junitxml=' + str(directory / 'privilege.xml'))
            result['privilege'] = json.loads((HERE / '.state/superuser-evidence.json').read_text())
            command('python3', '-m', 'pytest', '-v', '-s', str(HERE / 'test_access.py'),
                    '--junitxml=' + str(directory / 'access.xml'))
            if variant != 'baseline':
                command('python3', '-m', 'pytest', '-v', '-s', str(HERE / 'test_superuser_dba.py'),
                        '--junitxml=' + str(directory / 'dba.xml'))
                result['unprivileged_internal_dba'] = json.loads((HERE / '.state/superuser-dba-evidence.json').read_text())
            result['exit_code'] = 0
        except Exception as exc:
            result.update(exit_code=1, error=str(exc))
        finally:
            command('molecule', 'cleanup', '-s', 'integration', check=False)
            for suffix in ('containers.log', 'systemd.log'):
                path = HERE / '.state' / (config['version'] + '-' + suffix)
                if path.exists():
                    (directory / suffix).write_bytes(path.read_bytes())
            versions_path = HERE / '.state/server-versions.json'
            result['server_versions'] = json.loads(versions_path.read_text()) if versions_path.exists() else {}
            teardown = command('molecule', 'destroy', '-s', 'integration', check=False)
            result['teardown_exit_code'] = teardown.returncode
    result['elapsed_seconds'] = round(time.monotonic() - start, 1)
    result['artifact_unchanged'] = hashlib.sha256(jar.read_bytes()).hexdigest() == digest
    result['test_inputs_unchanged'] = all(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest
                                        for name, digest in test_hashes.items())
    if not result['artifact_unchanged'] or not result['test_inputs_unchanged'] or result['teardown_exit_code']:
        result['exit_code'] = 1
    if result['server_versions'] != {'cassandra1': config['version'], 'cassandra2': config['version']}:
        result['exit_code'] = 1
    for name, expected in [('privilege', 1), ('access', 15)] + ([] if variant == 'baseline' else [('dba', 1)]):
        path = directory / (name + '.xml')
        if not path.exists():
            result['exit_code'] = 1
            continue
        suites = list(ET.parse(path).getroot().iter('testsuite'))
        counts = {key: sum(int(s.get(key, 0)) for s in suites)
                  for key in ('tests', 'failures', 'errors', 'skipped')}
        result[name + '_tests'] = counts
        if counts != dict(tests=expected, failures=0, errors=0, skipped=0):
            result['exit_code'] = 1
    (directory / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('modules', nargs='*', default=['4.1', '4.0', '5.0', '3.11', '3.0', '2.2'])
    parser.add_argument('--variants', nargs='+', choices=['baseline', 'demoted', 'unprivileged', 'absent'])
    args = parser.parse_args()
    versions = json.loads((HERE / 'matrix.json').read_text())
    arch = subprocess.check_output(['docker', 'version', '--format', '{{.Server.Arch}}'], text=True).strip()
    summary_path = OUTPUT / 'summary.json'
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    failed = False
    for module in args.modules:
        variants = args.variants or (['baseline', 'demoted', 'unprivileged', 'absent'] if module == '4.1'
                                     else ['unprivileged', 'absent'])
        for variant in variants:
            result = run_case(module, variant, versions[module], 'linux/' + arch)
            summary[module + '/' + variant] = result
            summary_path.write_text(json.dumps(summary, indent=2) + '\n')
            failed = failed or bool(result['exit_code'])
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
