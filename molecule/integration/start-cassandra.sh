#!/bin/bash
set -eu
config=/etc/cassandra/cassandra.yaml
mode=$(cat /suite/.state/mode)
export JVM_EXTRA_OPTS="${JVM_EXTRA_OPTS:-} -Dcassandra.ring_delay_ms=1000"
authenticator=PasswordAuthenticator
manager=CassandraRoleManager
if [ "$mode" = plugin ]; then
  authenticator=${LDAP_AUTHENTICATOR:-LDAPAuthenticator}
  manager=LDAPCassandraRoleManager
  cp /suite/.state/ldap.yaml /etc/cassandra/ldap.yaml
  export JVM_EXTRA_OPTS="${JVM_EXTRA_OPTS:-} -Dcassandra.ldap.config.file=/suite/.state/ldap.yaml"
fi
sed -i -E "s/^authenticator:.*/authenticator: $authenticator/; s/^role_manager:.*/role_manager: $manager/; s/^authorizer:.*/authorizer: CassandraAuthorizer/; s/^permissions_validity_in_ms:.*/permissions_validity_in_ms: 200/; s/^roles_validity_in_ms:.*/roles_validity_in_ms: 200/; s/^credentials_validity_in_ms:.*/credentials_validity_in_ms: 200/" "$config"
if grep -q 'auth_write_consistency_level' "$config"; then
  sed -i '/^auth_write_consistency_level:/d; /^auth_read_consistency_level:/d' "$config"
  printf '\nauth_write_consistency_level: QUORUM\nauth_read_consistency_level: QUORUM\n' >> "$config"
fi
if command -v docker-entrypoint.sh >/dev/null 2>&1; then
  exec docker-entrypoint.sh cassandra -f
fi
exec /docker-entrypoint.sh cassandra -f
