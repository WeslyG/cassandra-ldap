"""The internal Cassandra administrator must not be confused with LDAP bind."""
import json
import os

from harness import STATE, change_policy, compose, connection, eventually
from test_access import denied_login, user_query
from cassandra.cluster import NoHostAvailable
from test_superuser import forbidden_service_actions, service_role
import yaml


def test_unprivileged_internal_dba_provisioning_probe():
    assert os.environ['LDAP_SUPERUSER_EXPERIMENT'] != 'baseline'
    evidence = {}
    if os.environ['LDAP_SUPERUSER_EXPERIMENT'] == 'absent':
        assert service_role() is None
        evidence['bind_role_absent_through_full_access_lifecycle'] = True
        user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (24,'ordinary-service-login')", 'svc_ldap', 'admin')
        assert not service_role().is_superuser
        forbidden_service_actions()
        evidence['later_service_login_created_only_ordinary_role'] = True
    config = yaml.safe_load((STATE / 'ldap.yaml').read_text())
    modified = dict(config, cassandra_ldap_admin_user='cn=svc_ldap,dc=example,dc=org')
    compose('exec', '-T', 'ldap', 'ldapadd', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
            input='dn: cn=charlie,dc=example,dc=org\nobjectClass: inetOrgPerson\ncn: charlie\nsn: User\nuid: charlie\nuserPassword: test\n')
    compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
            input='dn: cn=readers,dc=example,dc=org\nchangetype: modify\nadd: member\nmember: cn=charlie,dc=example,dc=org\n')
    try:
        change_policy(modified)
        for node in ('cassandra1', 'cassandra2'):
            try:
                user_query(node, "INSERT INTO app.records (id,value) VALUES (20,'dba-probe')", 'charlie', 'test')
                evidence[node] = {'provisioned_and_writable': True}
            except NoHostAvailable as exc:
                evidence[node] = {'provisioned_and_writable': False,
                                  'errors': [str(error) for error in exc.errors.values()]}
        if all(evidence[node]['provisioned_and_writable'] for node in ('cassandra1', 'cassandra2')):
            compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
                    input='dn: cn=readers,dc=example,dc=org\nchangetype: modify\ndelete: member\nmember: cn=charlie,dc=example,dc=org\n')
            def revoked():
                with connection() as session:
                    row = session.execute('SELECT permissions FROM system_auth.role_permissions WHERE role=%s AND resource=%s',
                                          ('cn=charlie,dc=example,dc=org', 'data/app')).one()
                    assert not row or not row.permissions
            eventually(revoked, 180)
            denied_login('cassandra1', 'charlie', 'test')
            compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
                    input='dn: cn=readers,dc=example,dc=org\nchangetype: modify\nadd: member\nmember: cn=charlie,dc=example,dc=org\n')
            user_query('cassandra2', "INSERT INTO app.records (id,value) VALUES (23,'internal-dba-regrant')", 'charlie', 'test')
            evidence['unprivileged_dba_revoke_and_regrant'] = True
    finally:
        change_policy(config)
    user_query('cassandra1', "INSERT INTO app.records (id,value) VALUES (21,'native-dba-restored')", 'charlie', 'test')
    compose('exec', '-T', 'ldap', 'ldapmodify', '-x', '-D', 'cn=admin,dc=example,dc=org', '-w', 'admin',
            input='dn: cn=readers,dc=example,dc=org\nchangetype: modify\ndelete: member\nmember: cn=svc_ldap,dc=example,dc=org\n')
    for node in ('cassandra1', 'cassandra2'):
        denied_login(node, 'svc_ldap', 'admin')
        user_query(node, "INSERT INTO app.records (id,value) VALUES (22,'bind-without-mapped-group')", 'charlie', 'test')
    evidence['bind_without_mapped_group'] = {'service_login_denied': True, 'ordinary_user_login_succeeded': True}
    data = json.dumps(evidence, indent=2) + '\n'
    (STATE / 'superuser-dba-evidence.json').write_text(data)
    versions = json.loads((STATE.parent / 'matrix.json').read_text())
    module = next(key for key, value in versions.items() if value['version'] == os.environ['CASSANDRA_VERSION'])
    report = STATE / 'superuser-experiment/reports' / module / os.environ['LDAP_SUPERUSER_EXPERIMENT']
    (report / 'dba-evidence.json').write_text(data)
