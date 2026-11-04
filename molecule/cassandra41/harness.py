"""Isolated Docker fixtures. All credentials and data are disposable test fixtures."""
import argparse
import contextlib
import hashlib
import base64
import json
import os
import pathlib
import subprocess
import time
import socket

import yaml
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.policies import WhiteListRoundRobinPolicy
from cassandra import ConsistencyLevel

HERE = pathlib.Path(__file__).resolve().parent
STATE = HERE / '.state'
DN = 'cn=alice,dc=example,dc=org'


def compose(*args, input=None, check=True):
    return subprocess.run(['docker', 'compose', '-f', str(HERE / 'compose.yaml'), *args],
                          input=input, text=True, capture_output=True, check=check)


def port(node):
    return int(compose('port', node, '9042').stdout.strip().rsplit(':', 1)[1])


@contextlib.contextmanager
def connection(node='cassandra1', username='cassandra', password='cassandra'):
    address = socket.gethostbyname(node) if os.environ.get('LDAP41_RUNNER') else '127.0.0.1'
    native_port = 9042 if os.environ.get('LDAP41_RUNNER') else port(node)
    cluster = Cluster([address], port=native_port, protocol_version=4,
                      auth_provider=PlainTextAuthProvider(username, password),
                      load_balancing_policy=WhiteListRoundRobinPolicy([address]),
                      connect_timeout=15, control_connection_timeout=15)
    try:
        session = cluster.connect()
        session.default_timeout = 20
        session.default_consistency_level = ConsistencyLevel.QUORUM
        yield session
    finally:
        cluster.shutdown()


def eventually(fn, timeout=240):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:
            last = exc
            time.sleep(2)
    raise AssertionError(f'Timed out waiting for {fn}: {last}') from last


def ready(node):
    with connection(node) as session:
        assert session.execute('SELECT release_version FROM system.local').one()


def ldap_modify(ldif):
    return compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-H', 'ldap://localhost',
                   '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin', input=ldif)


def group_member(group, present):
    operation = 'add' if present else 'delete'
    ldap_modify(f'dn: cn={group},dc=example,dc=org\nchangetype: modify\n{operation}: member\nmember: {DN}\n')


def fingerprint(config):
    entries = [config['ldap_uri'], config['ldap_filter_template'], config['ldap_service_dn']]
    for mapping in config['group_role_mappings']:
        dn = mapping['ldap_group_dn'].lower()
        for target in mapping['cassandra_roles']:
            if isinstance(target, str):
                entries.append(dn + '\0role\0' + target)
            else:
                grants = ['CREATE', 'ALTER', 'DROP', 'SELECT', 'MODIFY', 'AUTHORIZE'] if target['grant'] == 'ALL' else [target['grant']]
                for grant in grants:
                    encoded = grant + ':' + base64.b64encode(target['keyspace'].encode()).decode()
                    entries.append(dn + '\0permission\0' + encoded)
    digest = hashlib.sha256()
    for entry in sorted(entries):
        data = entry.encode()
        digest.update(len(data).to_bytes(4, 'big'))
        digest.update(data)
    return base64.b64encode(digest.digest()).decode()


def change_policy(config):
    # CAS prevents a policy transition during an active synchronization.
    def activate():
        with connection() as session:
            row = session.execute("UPDATE ldap_auth.coordinator SET policy=%s WHERE id='global' IF owner=null",
                                  (fingerprint(config),)).one()
            assert row.applied
    eventually(activate)
    (STATE / 'ldap.yaml').write_text(yaml.safe_dump(config))
    for node in ['cassandra1', 'cassandra2']:
        compose('restart', node)
        eventually(lambda: ready(node))


def converge():
    for node in ['cassandra1', 'cassandra2']:
        eventually(lambda: ready(node))
    if (STATE / 'mode').read_text().strip() == 'plugin':
        print('UNCHANGED')
        return
    def seed_ldap():
        result = compose('exec', '-T', 'ldap', 'ldapadd', '-x', '-H', 'ldap://localhost',
                         '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
                         input=(HERE / 'ldap.ldif').read_text(), check=False)
        assert result.returncode in (0, 68), result.stderr
    eventually(seed_ldap)
    with connection() as session:
        statements = [
            "ALTER KEYSPACE system_auth WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':2}",
            "CREATE KEYSPACE IF NOT EXISTS ldap_auth WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':2}",
            "CREATE KEYSPACE IF NOT EXISTS app WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':2}",
            "CREATE KEYSPACE IF NOT EXISTS manual WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':2}",
            "CREATE TABLE IF NOT EXISTS app.records (id int PRIMARY KEY, value text)",
            "INSERT INTO app.records (id,value) VALUES (1,'fixture')",
            "CREATE ROLE IF NOT EXISTS reader_role",
            "CREATE ROLE IF NOT EXISTS writer_role",
            "CREATE ROLE IF NOT EXISTS manual_role",
        ]
        for statement in statements:
            session.execute(statement)
        schema = (HERE / '../../conf/access-sync-schema.cql').resolve().read_text()
        schema = '\n'.join(line for line in schema.splitlines() if not line.startswith('--'))
        for statement in schema.split(';'):
            if statement.strip():
                session.execute(statement)
    compose('exec', '-T', 'cassandra1', 'nodetool', 'repair', 'system_auth')
    (STATE / 'mode').write_text('plugin')
    for node in ['cassandra1', 'cassandra2']:
        compose('restart', node)
        eventually(lambda: ready(node))

    print('DEPLOYED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['converge'])
    parser.parse_args()
    converge()
