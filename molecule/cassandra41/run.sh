#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
docker build -t ldap41-integration-runner -f molecule/cassandra41/Dockerfile molecule/cassandra41
if ! docker network inspect ldap41-integration_default >/dev/null 2>&1; then
  docker network create --label codex.task=ldap41-integration ldap41-integration_default
fi
exec docker run --rm --name ldap41-integration-runner \
  --network ldap41-integration_default \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$root:$root" -w "$root" \
  -e ANSIBLE_LOCAL_TEMP=/tmp/ansible-local \
  --entrypoint molecule ldap41-integration-runner "${@:-test}" -s cassandra41
