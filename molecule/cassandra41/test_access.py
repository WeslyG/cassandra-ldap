import concurrent.futures
import json
import time
import uuid
import pytest
import yaml
from cassandra import AuthenticationFailed, Unauthorized
from cassandra.cluster import NoHostAvailable
from harness import HERE, STATE, DN, connection, eventually, compose, group_member, change_policy, ready


def user_query(node, query, username='alice', password='test'):
    with connection(node, username, password) as session:
        return list(session.execute(query))


def denied_login(node, username, password):
    with pytest.raises(NoHostAvailable) as failure:
        user_query(node, 'SELECT * FROM app.records', username, password)
    assert failure.value.errors
    assert all(isinstance(error, AuthenticationFailed) for error in failure.value.errors.values()), failure.value


def direct_permissions():
    with connection() as session:
        rows = session.execute('SELECT resource, permissions FROM system_auth.role_permissions WHERE role=%s', (DN,))
        return {row.resource: set(row.permissions or ()) for row in rows}


def memberships():
    with connection() as session:
        return set(session.execute('SELECT member_of FROM system_auth.roles WHERE role=%s', (DN,)).one().member_of or ())


def test_01_login_and_union():
    for node in ['cassandra1', 'cassandra2']:
        assert user_query(node, 'SELECT * FROM app.records')
        user_query(node, "INSERT INTO app.records (id,value) VALUES (2,'allowed')")
    assert {'reader_role', 'writer_role'} <= memberships()
    assert {'SELECT', 'MODIFY', 'CREATE', 'ALTER', 'DROP', 'AUTHORIZE'} <= direct_permissions()['data/app']
    with connection() as session:
        session.execute("GRANT manual_role TO '%s'" % DN)
        session.execute("GRANT SELECT ON KEYSPACE manual TO '%s'" % DN)


@pytest.mark.parametrize('username,password', [('alice', 'wrong'), ('alice', ''), ('bob', 'test'), ('*)(uid=*)', 'test')])
def test_02_invalid_login(username, password):
    denied_login('cassandra1', username, password)


def test_03_parallel_logins():
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(user_query, 'cassandra1' if i % 2 else 'cassandra2', 'SELECT * FROM app.records') for i in range(4)]
        assert all(future.result() for future in futures)


def test_04_group_removal_revokes_and_preserves_manual():
    with connection('cassandra2', 'alice', 'test') as existing:
        group_member('writers', False)
        user_query('cassandra1', 'SELECT * FROM app.records')
        def assert_revoked():
            assert direct_permissions()['data/app'] == {'SELECT'}
            assert memberships() == {'reader_role', 'manual_role'}
            assert direct_permissions()['data/manual'] == {'SELECT'}
            with pytest.raises(Unauthorized):
                existing.execute("INSERT INTO app.records (id,value) VALUES (3,'forbidden')")
        eventually(assert_revoked, 90)


def test_05_yaml_removal_revokes_previous_grants():
    config = yaml.safe_load((STATE / 'ldap.yaml').read_text())
    config['group_role_mappings'][0]['cassandra_roles'] = [{'grant': 'MODIFY', 'keyspace': 'app'}]
    change_policy(config)
    user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (4,'changed')")
    assert direct_permissions()['data/app'] == {'MODIFY'}
    assert memberships() == {'manual_role'}
    with pytest.raises(Unauthorized):
        user_query('cassandra2', 'SELECT * FROM app.records')


def test_05b_group_addition_restores_permissions():
    group_member('writers', True)
    try:
        user_query('cassandra2', "INSERT INTO app.records (id,value) VALUES (9,'group-added')")
        assert 'writer_role' in memberships()
        assert 'SELECT' in direct_permissions()['data/app']
        for node in ['cassandra1', 'cassandra2']:
            def assert_readable():
                assert user_query(node, 'SELECT * FROM app.records')
            eventually(assert_readable, 30)
    finally:
        group_member('writers', False)
    user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (5,'restored')")
    assert direct_permissions()['data/app'] == {'MODIFY'}


def test_06_ldap_outage_does_not_revoke():
    before = direct_permissions()
    compose('stop', 'ldap')
    try:
        with pytest.raises(NoHostAvailable):
            user_query('cassandra1', 'SELECT * FROM app.records')
        assert direct_permissions() == before
    finally:
        compose('start', 'ldap')


def test_06b_policy_mismatch_rejects_without_changing_grants():
    eventually(lambda: compose('exec', '-T', 'ldap', 'ldapwhoami', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin'))
    before = direct_permissions()
    with connection() as session:
        active = session.execute("SELECT policy FROM ldap_auth.coordinator WHERE id='global'").one().policy
        def replace_policy(value):
            assert session.execute("UPDATE ldap_auth.coordinator SET policy=%s WHERE id='global' IF owner=null", (value,)).one().applied
        eventually(lambda: replace_policy('deliberate-test-mismatch'))
        try:
            denied_login('cassandra1', 'alice', 'test')
            denied_login('cassandra2', 'alice', 'test')
            assert direct_permissions() == before
        finally:
            eventually(lambda: replace_policy(active))


def test_06c_replica_outage_fails_closed():
    user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (7,'before-outage')")
    before = direct_permissions()
    compose('stop', 'cassandra2')
    try:
        with pytest.raises(NoHostAvailable):
            user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (7,'no-quorum')")
    finally:
        compose('start', 'cassandra2')
        eventually(lambda: ready('cassandra2'))
    assert direct_permissions() == before


def test_06d_abandoned_lock_blocks_and_can_be_recovered():
    owner = uuid.uuid4()
    before = direct_permissions()
    with connection() as session:
        def acquire():
            assert session.execute("UPDATE ldap_auth.coordinator SET owner=%s WHERE id='global' IF owner=null", (owner,)).one().applied
        eventually(acquire)
        try:
            denied_login('cassandra1', 'alice', 'test')
            assert direct_permissions() == before
        finally:
            assert session.execute("UPDATE ldap_auth.coordinator SET owner=null WHERE id='global' IF owner=%s", (owner,)).one().applied
    user_query('cassandra2', "INSERT INTO app.records (id,value) VALUES (8,'recovered')")


def test_07_background_revocation_without_login():
    group_member('readers', False)
    def assert_revoked():
        assert direct_permissions().get('data/app', set()) == set()
        assert memberships() == {'manual_role'}
        assert direct_permissions()['data/manual'] == {'SELECT'}
    eventually(assert_revoked, 180)
    denied_login('cassandra1', 'alice', 'test')
    denied_login('cassandra2', 'alice', 'test')


def test_08_deleted_user_background_revocation():
    group_member('readers', True)
    user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (6,'before-delete')")
    compose('exec', '-T', 'ldap', 'ldapdelete', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin', DN)
    def assert_revoked():
        assert not direct_permissions().get('data/app')
        assert direct_permissions()['data/manual'] == {'SELECT'}
        assert memberships() == {'manual_role'}
    eventually(assert_revoked, 180)
    denied_login('cassandra1', 'alice', 'test')
