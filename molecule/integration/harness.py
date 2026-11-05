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
import uuid

import yaml
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.policies import WhiteListRoundRobinPolicy
from cassandra import ConsistencyLevel
from cassandra.query import SimpleStatement

HERE = pathlib.Path(__file__).resolve().parent
STATE = HERE / '.state'
DN = 'cn=alice,dc=example,dc=org'


def compose(*args, input=None, check=True, timeout=600):
    result = subprocess.run(['docker', 'compose', '-f', str(HERE / 'compose.yaml'), *args],
                            input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'Docker Compose {args} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}')
    return result


def port(node):
    return int(compose('port', node, '9042').stdout.strip().rsplit(':', 1)[1])


@contextlib.contextmanager
def connection(node='cassandra1', username='cassandra', password='cassandra'):
    address = socket.gethostbyname(node) if os.environ.get('LDAP_INTEGRATION_RUNNER') else '127.0.0.1'
    native_port = 9042 if os.environ.get('LDAP_INTEGRATION_RUNNER') else port(node)
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
        release = session.execute('SELECT release_version FROM system.local').one().release_version
        expected = os.environ.get('CASSANDRA_VERSION')
        if expected:
            assert release == expected, (node, release, expected)
        # Older servers open native transport before CassandraRoleManager is ready.
        # SELECT alone cannot establish that GRANT/REVOKE operations are available.
        session.execute('CREATE ROLE IF NOT EXISTS ldap_readiness_probe')
        session.execute('ALTER ROLE ldap_readiness_probe WITH LOGIN = false')
        evidence = STATE / 'server-versions.json'
        versions = json.loads(evidence.read_text()) if evidence.exists() else {}
        versions[node] = release
        evidence.write_text(json.dumps(versions, indent=2) + '\n')


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
                grants = json.loads((STATE / 'permission-names.json').read_text()) if target['grant'] == 'ALL' else [target['grant']]
                for grant in grants:
                    encoded = grant + ':' + base64.b64encode(target['keyspace'].encode()).decode()
                    entries.append(dn + '\0permission\0' + encoded)
    digest = hashlib.sha256()
    for entry in sorted(entries):
        data = entry.encode()
        digest.update(len(data).to_bytes(4, 'big'))
        digest.update(data)
    return base64.b64encode(digest.digest()).decode()


@contextlib.contextmanager
def maintenance():
    # Reserve an idle coordinator; never steal an existing writer's ownership.
    owner = uuid.uuid4()
    def reserve():
        with connection() as session:
            try:
                row = session.execute("UPDATE ldap_auth.coordinator SET owner=%s WHERE id='global' IF owner=null",
                                      (owner,)).one()
                if row.applied:
                    return
            except Exception:
                # Resolve a lost CAS reply before retrying or entering maintenance.
                pass
            row = session.execute(SimpleStatement(
                "SELECT owner FROM ldap_auth.coordinator WHERE id='global'",
                consistency_level=ConsistencyLevel.SERIAL)).one()
            assert row and row.owner == owner, 'Coordinator belongs to another writer'
    eventually(reserve)
    try:
        yield owner
    finally:
        with connection() as session:
            row = session.execute("UPDATE ldap_auth.coordinator SET owner=null WHERE id='global' IF owner=%s",
                                  (owner,)).one()
            assert row.applied, 'Maintenance ownership changed; refusing to clear another owner'


def change_policy(config):
    # Keep background writers out of their critical section while nodes restart.
    with maintenance() as owner:
        with connection() as session:
            row = session.execute("UPDATE ldap_auth.coordinator SET policy=%s WHERE id='global' IF owner=%s",
                                  (fingerprint(config), owner)).one()
            assert row.applied
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
            "ALTER KEYSPACE system_auth WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':'2'}",
            "CREATE KEYSPACE IF NOT EXISTS ldap_auth WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':'2'}",
            "CREATE KEYSPACE IF NOT EXISTS app WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':'2'}",
            "CREATE KEYSPACE IF NOT EXISTS manual WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':'2'}",
            "CREATE TABLE IF NOT EXISTS app.records (id int PRIMARY KEY, value text)",
            "INSERT INTO app.records (id,value) VALUES (1,'fixture')",
            "CREATE ROLE IF NOT EXISTS reader_role",
            "CREATE ROLE IF NOT EXISTS writer_role",
            "CREATE ROLE IF NOT EXISTS manual_role",
        ]
        for statement in statements:
            session.execute(statement)
        session.execute('CREATE ROLE IF NOT EXISTS permission_probe')
        session.execute('GRANT ALL ON KEYSPACE app TO permission_probe')
        permissions = session.execute("SELECT permissions FROM system_auth.role_permissions WHERE role='permission_probe' AND resource='data/app'").one().permissions
        (STATE / 'permission-names.json').write_text(json.dumps(sorted(permissions)))
        session.execute('DROP ROLE permission_probe')
        schema = (HERE / '../../conf/access-sync-schema.cql').resolve().read_text()
        schema = '\n'.join(line for line in schema.splitlines() if not line.startswith('--'))
        for statement in schema.split(';'):
            if statement.strip():
                session.execute(statement)
    # Cassandra 2.2's NodeProbe brackets IPv4 literals, rejected by recent Java 8.
    # Use a valid IPv4-mapped IPv6 literal instead of weakening JNDI URL parsing.
    host = ['-h', '::ffff:127.0.0.1'] if os.environ.get('CASSANDRA_VERSION', '').startswith('2.2.') else []
    compose('exec', '-T', 'cassandra1', 'nodetool', *host, 'repair', '-full', '-seq', 'system_auth')
    (STATE / 'mode').write_text('plugin')
    for node in ['cassandra1', 'cassandra2']:
        compose('restart', node)
        eventually(lambda: ready(node))

    print('DEPLOYED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['converge', 'ready-seed'])
    args = parser.parse_args()
    if args.action == 'ready-seed':
        eventually(lambda: ready('cassandra1'))
        # Keep the original admin replica in the replica set when node 2 joins.
        # Otherwise RF=1 can move its partition to a node with no auth data yet.
        with connection() as session:
            session.execute("ALTER KEYSPACE system_auth WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':'2'}")
    else:
        converge()
