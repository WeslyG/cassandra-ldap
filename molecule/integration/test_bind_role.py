"""The directory bind identity must not become an implicit Cassandra administrator."""
import pytest
import yaml

from harness import STATE, connection, compose, eventually, maintenance, ready


def bind_dn():
    return yaml.safe_load((STATE / 'ldap.yaml').read_text())['ldap_service_dn']


def role():
    with connection() as session:
        return session.execute('SELECT is_superuser, can_login, member_of FROM system_auth.roles WHERE role=%s',
                               (bind_dn(),)).one()


def test_bind_role_not_created_by_startup_or_user_authentication():
    assert role() is None
    for node in ('cassandra1', 'cassandra2'):
        with connection(node, 'alice', 'test') as session:
            assert session.execute('SELECT * FROM app.records').one()
    assert role() is None


@pytest.mark.parametrize('superuser', [False, True])
def test_existing_bind_role_is_preserved_across_restart(superuser):
    quoted = '"' + bind_dn().replace('"', '""') + '"'
    with maintenance():
        try:
            with connection() as session:
                session.execute('CREATE ROLE ' + quoted + ' WITH LOGIN=false AND SUPERUSER=' + str(superuser).lower())
                session.execute('GRANT manual_role TO ' + quoted)
                session.execute('GRANT SELECT ON KEYSPACE manual TO ' + quoted)
                assert list(session.execute('LIST ROLES OF ' + quoted))
                assert list(session.execute('LIST ALL PERMISSIONS OF ' + quoted))
            for node in ('cassandra1', 'cassandra2'):
                compose('restart', node)
                eventually(lambda: ready(node))
            def preserved():
                current = role()
                assert current and current.is_superuser == superuser and not current.can_login
                assert set(current.member_of or ()) == {'manual_role'}
                with connection() as session:
                    permissions = session.execute('SELECT permissions FROM system_auth.role_permissions WHERE role=%s AND resource=%s',
                                                  (bind_dn(), 'data/manual')).one()
                    assert permissions and set(permissions.permissions) == {'SELECT'}
            eventually(preserved)
        finally:
            with connection() as session:
                session.execute('DROP ROLE IF EXISTS ' + quoted)
    for node in ('cassandra1', 'cassandra2'):
        with connection(node, 'alice', 'test') as session:
            assert session.execute('SELECT * FROM app.records').one()
    assert role() is None
