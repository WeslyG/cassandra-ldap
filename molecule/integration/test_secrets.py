"""Exercise the real plugin on both nodes, including PID-1 systemd decryption."""
import os

import pytest
import yaml

from harness import STATE, change_policy, compose, connection, eventually, ready, maintenance

SYSTEMD = os.environ.get('LDAP_TEST_SYSTEMD') == 'true'
SOURCES = ['inline', 'env', 'file'] + (['credential'] if SYSTEMD else [])


def config_for(source):
    config = yaml.safe_load((STATE / 'ldap.yaml').read_text())
    for key in list(config):
        if key.startswith('ldap_service_password'):
            del config[key]
    key, value = {
        'inline': ('ldap_service_password', 'admin'),
        'env': ('ldap_service_password_env', 'LDAP_TEST_BIND_PASSWORD'),
        'file': ('ldap_service_password_file', '/etc/cassandra/ldap-bind-password.txt'),
        'credential': ('ldap_service_password_credential', 'ldap-bind-password'),
    }[source]
    config[key] = value
    return config


def ldap_login():
    for node in ['cassandra1', 'cassandra2']:
        with connection(node, 'alice', 'test') as session:
            assert session.execute('SELECT * FROM app.records').one().value == 'fixture'


def write_fixture(node, path, content, owner='root:root'):
    # All paths/content are fixed disposable fixtures, never production credentials.
    writer = 'cat' if content else ':'
    compose('exec', '-T', node, 'bash', '-c',
            f'{writer} > {path} && chown {owner} {path} && chmod 0600 {path}', input=content or None)


@pytest.mark.parametrize('source', SOURCES)
def test_01_secret_source(source):
    for node in ['cassandra1', 'cassandra2']:
        write_fixture(node, '/etc/cassandra/ldap-bind-password.txt', 'admin\r\n', 'cassandra:cassandra')
        if SYSTEMD:
            write_fixture(node, '/etc/cassandra/ldap-test.env',
                          'LDAP_TEST_BIND_PASSWORD=admin\n' if source == 'env' else '')
    change_policy(config_for(source))
    ldap_login()


def failed_start(node):
    if SYSTEMD:
        state = compose('exec', '-T', node, 'systemctl', 'show', 'cassandra', '-p', 'ActiveState', '--value').stdout.strip()
        assert state == 'failed', state
    else:
        state = compose('ps', '-a', '--format', 'json', node).stdout
        assert 'exited' in state.lower(), state


def test_02_missing_env_fails_startup_without_fallback():
    original = (STATE / 'ldap.yaml').read_text()
    config = config_for('env')
    config['ldap_service_password_env'] = 'LDAP_TEST_MISSING'
    with maintenance():
        try:
            (STATE / 'ldap.yaml').write_text(yaml.safe_dump(config))
            compose('restart', 'cassandra1')
            eventually(lambda: failed_start('cassandra1'), 90)
            logs = (compose('exec', '-T', 'cassandra1', 'journalctl', '-u', 'cassandra', '--no-pager').stdout
                    if SYSTEMD else compose('logs', '--no-color', 'cassandra1').stdout)
            assert 'LDAP service password is missing' in logs
        finally:
            (STATE / 'ldap.yaml').write_text(original)
            compose('start' if not SYSTEMD else 'restart', 'cassandra1')
            eventually(lambda: ready('cassandra1'))
    ldap_login()


def assert_systemd_service():
    for node in ['cassandra1', 'cassandra2']:
        assert compose('exec', '-T', node, 'cat', '/proc/1/comm').stdout.strip() == 'systemd'
        assert compose('exec', '-T', node, 'systemctl', 'show', 'cassandra', '-p', 'User', '--value').stdout.strip() == 'cassandra'
        # Read the Java process environment, not an artificial docker-exec environment.
        probe = '''pid=$(systemctl show cassandra -p MainPID --value)
test "$(stat -c %U /proc/$pid)" = cassandra
tr '\\0' '\\n' < /proc/$pid/environ | grep '^CREDENTIALS_DIRECTORY='
if tr '\\0' '\\n' < /proc/$pid/environ | grep -q '^LDAP_TEST_BIND_PASSWORD='; then
  exit 1
fi
test -s /var/lib/systemd/credential.secret
systemctl cat cassandra
'''
        evidence = compose('exec', '-T', node, 'bash', '-e', '-c', probe).stdout
        assert 'CREDENTIALS_DIRECTORY=' in evidence
        assert 'LoadCredentialEncrypted=ldap-bind-password:' in evidence


if SYSTEMD:
    def test_03_real_systemd_service():
        assert yaml.safe_load((STATE / 'ldap.yaml').read_text()).get('ldap_service_password_credential') == 'ldap-bind-password'
        assert_systemd_service()
        ldap_login()

    def test_04_tampered_ciphertext_prevents_service_start():
        node = 'cassandra1'
        path = '/etc/credstore.encrypted/ldap-bind-password.cred'
        compose('exec', '-T', node, 'cp', path, path + '.backup')
        with maintenance():
            try:
                write_fixture(node, path, 'not-an-authenticated-credential\n')
                compose('exec', '-T', node, 'systemctl', 'restart', 'cassandra', check=False)
                eventually(lambda: failed_start(node), 30)
                status = compose('exec', '-T', node, 'systemctl', 'show', 'cassandra', '-p', 'ExecMainStatus').stdout
                assert '243' in status, status  # systemd EXIT_CREDENTIALS, not a Java auth error.
            finally:
                compose('exec', '-T', node, 'mv', path + '.backup', path)
                compose('exec', '-T', node, 'systemctl', 'restart', 'cassandra')
                eventually(lambda: ready(node))
        ldap_login()

    def test_05_credential_rotation_on_restart():
        node = 'cassandra1'
        path = '/etc/credstore.encrypted/ldap-bind-password.cred'
        compose('exec', '-T', node, 'cp', path, path + '.backup')
        encrypt = ['systemd-creds', 'encrypt', '--with-key=host', '--name=ldap-bind-password', '-', path + '.new']
        try:
            compose('exec', '-T', node, *encrypt, input='wrong-fixture-password')
            compose('exec', '-T', node, 'mv', path + '.new', path)
            # Active service still has its original immutable credential.
            ldap_login()
            with maintenance():
                compose('exec', '-T', node, 'systemctl', 'restart', 'cassandra')
                eventually(lambda: ready(node))
            from test_access import denied_login
            denied_login(node, 'alice', 'test')
        finally:
            with maintenance():
                compose('exec', '-T', node, 'mv', path + '.backup', path)
                compose('exec', '-T', node, 'systemctl', 'restart', 'cassandra')
                eventually(lambda: ready(node))
        assert_systemd_service()
        ldap_login()
