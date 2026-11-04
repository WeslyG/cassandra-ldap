#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
docker build -t ldap41-integration-runner -f molecule/cassandra41/Dockerfile molecule/cassandra41
if ! docker network inspect ldap41-integration_default >/dev/null 2>&1; then
  docker network create --label codex.task=ldap41-integration ldap41-integration_default
fi
entrypoint=molecule
if [ "${1:-}" = matrix ]; then
  shift
  docker build -t ldap-integration-cassandra:2.2.19 -f molecule/cassandra41/Dockerfile.cassandra22 molecule/cassandra41
  entrypoint=python3
  set -- "$root/molecule/cassandra41/matrix.py" "$@"
else
  set -- "${@:-test}" -s cassandra41
fi
exec docker run --rm --name ldap41-integration-runner \
  --network ldap41-integration_default \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$root:$root" -w "$root" \
  -e ANSIBLE_LOCAL_TEMP=/tmp/ansible-local \
  -e CASSANDRA_IMAGE -e CASSANDRA_PLATFORM -e LDAP_PLUGIN_JAR -e LDAP_AUTHENTICATOR -e CASSANDRA_VERSION \
  --entrypoint "$entrypoint" ldap41-integration-runner "$@"
