# Cassandra 4.1 integration scenario

Runner image uses `weslyg/ansible-infra:ansible12-2026.11.04` with Cassandra driver
added. Ansible, Molecule and Python execute in the runner; Java is built separately.
Test fixtures use disposable credentials.
The compose project is `ldap41-integration`; it does not publish fixed host ports.
Two Cassandra 4.1.10 nodes share a DC and use RF=2. OpenLDAP runs on the same
private network. Allow approximately 3 GB of Docker memory and several minutes.

```sh
make integration-4.1
```

Run this make target on the host, where the Java build is available. For an
interactive devcontainer, open `.devcontainer/devcontainer.json` and run
`molecule test -s cassandra41` after building the jar separately.

Molecule delegates Docker Compose lifecycle to local Ansible playbooks. The
converge step bootstraps system_auth and the synchronization journal, repairs
system_auth, installs the policy and restarts with the plugin. Pytest verifies
real CQL access over both published native ports, including an existing session.

Results: `.state/results.xml`. Failed verification saves container logs to
`.state/containers.log`. For debugging, run create/converge/verify separately;
`make integration-4.1-destroy` removes only this scenario's containers and volumes.
The runner mounts the Docker socket and the workspace. Only run this trusted
scenario locally. A dedicated external Docker network is retained between runs.

OpenLDAP verifies direct membership and LDAP failures. It does not reproduce AD
account disabling, primary-group membership, or nested AD groups. A Samba AD
scenario is needed for those behaviors.

Behavioral coverage includes union of groups, invalid/empty passwords, filter
metacharacters, missing group DN, concurrent logins on both nodes, group removal
and re-addition, configuration changes, manual assignment preservation, access
from an existing connection, LDAP and replica outages, mismatched policy,
abandoned lock recovery, and background revocation after group/user deletion.
