#!/bin/bash
set -euo pipefail
if [ "${LDAP_TEST_SYSTEMD:-false}" != true ]; then
  exec /bin/bash /suite/start-cassandra.sh
fi
# Only the disposable privileged container's mount namespace is changed, not the host.
mount --make-rshared /
mkdir -p /etc/credstore.encrypted
chmod 0700 /etc/credstore.encrypted
if [ ! -f /etc/credstore.encrypted/ldap-bind-password.cred ]; then
  # Synthetic fixture only. A host-bound key is required; never --with-key=null.
  printf admin | systemd-creds encrypt --with-key=host --name=ldap-bind-password - /etc/credstore.encrypted/ldap-bind-password.cred
fi
chown -R cassandra:cassandra /etc/cassandra /var/lib/cassandra /var/log/cassandra
touch /etc/cassandra/ldap-test.env
chown root:root /etc/cassandra/ldap-test.env
chmod 0600 /etc/cassandra/ldap-test.env
exec /sbin/init
