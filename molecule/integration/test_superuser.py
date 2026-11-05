"""Destructive probes restricted to the disposable SUPERUSER experiment."""
import json
import os

import pytest
from cassandra import Unauthorized

from harness import STATE, connection, eventually, maintenance, compose, ready

SERVICE = 'cn=svc_ldap,dc=example,dc=org'


def service_query(query):
    with connection('cassandra1', 'svc_ldap', 'admin') as session:
        return list(session.execute(query))


def service_role():
    with connection() as session:
        return session.execute('SELECT is_superuser, can_login FROM system_auth.roles WHERE role=%s',
                               (SERVICE,)).one()


def forbidden_service_actions():
    with pytest.raises(Unauthorized):
        service_query('SELECT * FROM restricted.records')
    with pytest.raises(Unauthorized):
        service_query('CREATE ROLE escalation_probe WITH SUPERUSER=true AND LOGIN=false')


def test_service_privilege_boundary():
    variant = os.environ['LDAP_SUPERUSER_EXPERIMENT']
    with connection() as session:
        assert session.execute("SELECT is_superuser FROM system_auth.roles WHERE role='cassandra'").one().is_superuser
        session.execute("CREATE KEYSPACE restricted WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':'2'}")
        session.execute('CREATE TABLE restricted.records (id int PRIMARY KEY, value text)')
        session.execute("INSERT INTO restricted.records (id,value) VALUES (1,'outside-the-LDAP-policy')")
    initial = service_role()
    assert (initial is None) == (variant == 'absent')
    if initial:
        assert initial.is_superuser == (variant in ('baseline', 'demoted'))
        assert initial.can_login
    evidence = {'variant': variant, 'initial_role_exists': initial is not None,
                'initial_superuser': initial.is_superuser if initial else None}
    if variant in ('baseline', 'demoted'):
        assert service_query('SELECT * FROM restricted.records')
        service_query('CREATE ROLE escalation_probe WITH SUPERUSER=true AND LOGIN=false')
        with connection() as session:
            assert session.execute("SELECT is_superuser FROM system_auth.roles WHERE role='escalation_probe'").one().is_superuser
            session.execute('DROP ROLE escalation_probe')
        evidence['unmapped_data_read_and_superuser_creation'] = True
    if variant == 'demoted':
        with connection('cassandra2', 'svc_ldap', 'admin') as existing:
            with connection() as admin:
                admin.execute('ALTER ROLE "' + SERVICE + '" WITH SUPERUSER=false')
            def cached_session_loses_superuser():
                try:
                    existing.execute('SELECT * FROM restricted.records')
                except Unauthorized:
                    return
                raise AssertionError('Existing service session still has SUPERUSER access')
            eventually(cached_session_loses_superuser, 90)
        evidence['existing_session_lost_superuser'] = True
    if variant != 'baseline':
        # Check startup behavior before a service login can create an ordinary role.
        with maintenance():
            for node in ('cassandra1', 'cassandra2'):
                compose('restart', node)
                eventually(lambda: ready(node))
        after_restart = service_role()
        assert (after_restart is None) == (variant == 'absent')
        if after_restart:
            assert not after_restart.is_superuser
        if variant == 'absent':
            evidence['restart_kept_bind_role_absent'] = True
            # Keep it absent throughout the following full access lifecycle.
            (STATE / 'superuser-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
            return
        forbidden_service_actions()
        assert not service_role().is_superuser
        evidence['restart_did_not_elevate'] = True
        evidence['unmapped_data_and_superuser_creation_denied'] = True
    assert service_query('SELECT * FROM app.records')
    if variant == 'baseline':
        from test_access import denied_login, user_query
        compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
                input='dn: cn=readers,dc=example,dc=org\nchangetype: modify\ndelete: member\nmember: ' + SERVICE + '\n')
        try:
            denied_login('cassandra1', 'svc_ldap', 'admin')
            assert user_query('cassandra2', 'SELECT * FROM app.records')
        finally:
            compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
                    input='dn: cn=readers,dc=example,dc=org\nchangetype: modify\nadd: member\nmember: ' + SERVICE + '\n')
        evidence['superuser_still_requires_mapped_group'] = True
    (STATE / 'superuser-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
