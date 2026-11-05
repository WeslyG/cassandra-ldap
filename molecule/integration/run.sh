#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
docker build -t cassandra-ldap-integration-runner -f molecule/integration/Dockerfile molecule/integration
if ! docker network inspect cassandra-ldap-integration_default >/dev/null 2>&1; then
  docker network create --label cassandra-ldap.scope=integration cassandra-ldap-integration_default
fi
entrypoint=molecule
if [ "${1:-}" = superuser ]; then
  shift
  docker build -t ldap-integration-cassandra:2.2.19 -f molecule/integration/Dockerfile.cassandra22 molecule/integration
  entrypoint=python3
  set -- "$root/molecule/integration/superuser_experiment.py" "$@"
elif [ "${1:-}" = matrix ]; then
  shift
  docker build -t ldap-integration-cassandra:2.2.19 -f molecule/integration/Dockerfile.cassandra22 molecule/integration
  entrypoint=python3
  set -- "$root/molecule/integration/matrix.py" "$@"
else
  set -- "${@:-test}" -s integration
fi
exec docker run --rm --name cassandra-ldap-integration-runner \
  --network cassandra-ldap-integration_default \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$root:$root" -w "$root" \
  -e ANSIBLE_LOCAL_TEMP=/tmp/ansible-local \
  -e CASSANDRA_IMAGE -e CASSANDRA_PLATFORM -e LDAP_PLUGIN_JAR -e LDAP_AUTHENTICATOR -e CASSANDRA_VERSION -e LDAP_TEST_SYSTEMD -e LDAP_STOP_SIGNAL \
  --entrypoint "$entrypoint" cassandra-ldap-integration-runner "$@"
