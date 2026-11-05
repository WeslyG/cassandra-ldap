# Cluster Integration Tests

## Requirements and Isolation

The scenario name is `integration`; `matrix.json` selects the version adapters.
Run commands from the repository root on a host with Docker Compose v2, Bash,
Make, registry access and sufficient Docker resources. Allow at least 4 GB of
Docker memory for the test cluster; 6-8 GB is preferable when other services run.
A full systemd/secret-source matrix can take an hour or longer, depending on
image pulls, machine speed and rolling restarts.

Ansible, Molecule, pytest and the Cassandra Python driver run inside the image
built from `weslyg/ansible-infra:ansible12-2026.11.04`. Maven/Java builds use
`maven:3.9.9-eclipse-temurin-17`. Host Python and Ansible are not required.

Each version gets two Cassandra nodes in datacenter1 plus OpenLDAP 1.5.0,
isolated data volumes and an external Docker network. Both Cassandra nodes use
the same version and jar. The test is not a rolling version-upgrade test.
Keyspaces use NetworkTopologyStrategy with RF=2. Native CQL connections go
directly to each selected node; queries use QUORUM.

The runner mounts the Docker socket and repository. This gives it control over
the host Docker daemon: run only trusted code, without production credentials.
The Compose project, runner and network use the fixed name prefix
`cassandra-ldap-integration`. Do not run multiple copies or versions concurrently.
Published LDAP/CQL ports are random and bound to loopback. The external network
is retained after teardown; test containers and volumes are disposable.

All directory passwords, native passwords, example.org DNs and users in this
scenario are synthetic public fixtures. Never substitute production credentials.

## Commands

Build all jars, run unit tests, and run the complete cluster matrix:

```sh
make integration-all
```

This is a local command. GitHub Actions and CircleCI run `make verify-fast` only:
builds, Java unit tests, packaging tests and documentation checks, without clusters.

Individual stages:

```sh
make build-all
make test-unit
make test-release
make check-docs
LDAP_TEST_SYSTEMD=true bash molecule/integration/run.sh matrix
```

Retest selected adapters without rebuilding jars:

```sh
LDAP_TEST_SYSTEMD=true bash molecule/integration/run.sh matrix 3.0 5.0
```

Run just the default 4.1 scenario using a prebuilt 4.1 jar:

```sh
bash molecule/integration/run.sh test
```

`make integration-4.1` combines the local-JDK 4.1 build and that scenario.
For the container-based workflow, prefer `make build-all` followed by the runner.
The devcontainer definition provides the same trusted socket/network access;
build jars separately before invoking Molecule inside it.

For debugging, runner actions `create`, `converge`, `verify`, `cleanup` and
`destroy` may be executed separately. Collect logs with `cleanup` before
`destroy`. `make integration-4.1-destroy` removes the scenario containers and
data volumes, not unrelated Docker resources.

## Lifecycle

1. Destroy the previous scenario's containers and volumes.
2. Start LDAP and the seed with PasswordAuthenticator. Verify its release and
   execute a role mutation; an open port alone is not sufficient readiness.
3. Set system_auth RF=2 before starting the joining node so the initial admin
   partition remains represented. Wait for the second node's role operations.
4. Load synthetic LDAP entries, roles, application keyspaces and journal schema.
   Probe the server's actual GRANT ALL keyspace permission set.
5. Perform a full sequential system_auth repair and switch both nodes to the
   LDAP plugin with rolling restarts.
6. Run converge again and require no changes (Molecule idempotence).
7. Execute the behavioral tests against the live cluster.
8. Preserve node/LDAP logs and destroy the scenario containers and volumes.

Planned restarts and replica outage injection reserve an idle coordinator with
a dedicated controller UUID before stopping a node. Background workers cannot
enter the grant/revoke critical section while this maintenance owner is present.
The controller releases only its own UUID after nodes recover. It does not steal
an existing writer's lock or add a TTL. This is test/operator coordination, not
a graceful-shutdown mechanism in the Java plugin.

The matrix hashes the jar before running and checks it again afterward.
It records actual release versions from both servers, not just image tags.
Do not rebuild a jar while its cluster test is running.

## Unit Tests

`make test-unit` runs 18 TestNG tests using the 4.1 module as a classpath for
the shared code:

| Class | Count | Coverage |
|---|---:|---|
| AccessPolicyTest | 4 | Group union/deduplication, removal of one group, empty desired access, exact keyspace journal encoding |
| LDAPSecurityTest | 3 | LDAP filter escaping; empty and missing password rejection before opening LDAP |
| DistributedQueryTest | 3 | CQL quote/question-mark handling, set element escaping, missing bind parameters |
| LdapSecretResolverTest | 8 | Exclusive sources, whitespace, ENV, UTF-8/file bounds, credential traversal/symlinks, safe YAML errors |

These tests do not start LDAP or Cassandra. They do not prove a running cluster
works or exhaustively test YAML parsing. Surefire XML reports are under
`cassandra-4.1/target/surefire-reports/`.

The Java module trees also contain embedded-cluster integration scaffolding.
It is not the supported end-to-end acceptance suite and is not run by
`make test-unit`; do not equate this target with an unrestricted `mvn test`.
The Docker/Molecule scenario is the real-cluster acceptance path.

`make check-docs` runs in the same runner without mounting the Docker socket.
It checks README YAML against the example file, Java defaults, Maven/matrix
versions, local documentation links, 18 unit annotations and collection of all
15 access cases and 4/8 secret-source cases (plain/systemd mode), without opening
database or LDAP connections.

## Behavioral Tests

`make integration-all` (also `make integration-systemd`) builds all six jars,
runs unit/packaging/documentation checks and executes the full matrix under
**real systemd**. Each version uses a fresh pair of privileged, private-cgroup
containers with systemd 252 as PID 1 and `User=cassandra`. The derived image keeps
the exact server distribution and Java runtime from the version's original image;
the Linux userspace is Debian 12. OpenLDAP is a separate disposable container.
Privileges apply only to these test nodes. Docker socket access is equally
privileged: do not run this scenario on an untrusted/shared Docker host.

The boot script performs `mount --make-rshared /` in its container mount namespace,
encrypts the synthetic bind secret with real `systemd-creds --with-key=host`, and
starts systemd. The actual Cassandra unit uses `LoadCredentialEncrypted=` and
`PrivateMounts=yes`. No test injects a fake CREDENTIALS_DIRECTORY. Do not change
host mount propagation or bind the host's credential store/cgroup tree into nodes.

Before the 15 access tests, `test_secrets.py` runs 8 cases per version:

| Case | Count | Verification |
|---|---:|---|
| Source selection | 4 | Inline, ENV via systemd EnvironmentFile, UTF-8 file with CRLF, real encrypted credential; LDAP login on both nodes |
| Missing ENV | 1 | Cassandra startup fails without fallback; recovery restores LDAP login |
| Service identity | 1 | PID 1 is systemd, unit/Java user is cassandra, actual JVM receives credential directory but not password ENV, host key exists |
| Damaged ciphertext | 1 | systemd rejects service activation with EXIT_CREDENTIALS before Java starts; restore and authenticate |
| Rotation | 1 | Old credential remains usable before restart, new wrong password rejects LDAP after restart, restored encrypted credential recovers login |

All nodes then run the access lifecycle with the credential source. Reports
include `secrets.xml`, `systemd.log` and `systemd_credentials` in summary JSON;
zero failures/errors/skips are required. The full matrix has 90 access and 48
secret-source checks. This verifies host-key encryption, not TPM binding, all
Linux distributions or a production package's privilege-dropping wrappers.

For a targeted systemd run without rebuilding artifacts:

```sh
LDAP_TEST_SYSTEMD=true bash molecule/integration/run.sh matrix 4.1
```

For the ordinary upstream Docker entrypoint (without systemd), use
`bash molecule/integration/run.sh matrix`. That mode runs 4 secret-source cases
(inline, ENV, file, missing ENV) in addition to the same 15 access cases. It is
useful for debugging but does not validate real systemd credentials.

Pytest collects 15 cases. The invalid-login test has four parameter combinations;
all other rows are single tests.

| Test | Cases | Assertions |
|---|---:|---|
| Login and group union | 1 | Login, SELECT and INSERT on both nodes; role union; ALL expansion; seed unrelated manual assignments |
| Invalid credentials/input | 4 | Wrong password, empty password, nonmember and filter metacharacters reject authentication |
| Parallel logins | 1 | Four concurrent connections distributed across both nodes succeed |
| Group removal | 1 | Remove writer membership; revoke owned role/permissions, retain manual grants; deny INSERT from an existing session |
| YAML policy change | 1 | Change the active fingerprint, roll nodes, remove stale grants and install the new permission |
| Group re-addition | 1 | Restore membership/access; removing it again removes the managed additions |
| LDAP outage | 1 | New LDAP login fails and existing recorded permissions do not change |
| Policy mismatch | 1 | Both nodes reject LDAP login without changing grants |
| Replica outage | 1 | New LDAP login fails without QUORUM; restart the replica and retain recorded permissions |
| Abandoned lock | 1 | Login fails while another owner holds the lock; conditional operator recovery restores login |
| Background group revocation | 1 | Remove the last allowed group; owned grants disappear without another user login |
| Background user deletion | 1 | Delete the LDAP entry; revoke owned access while retaining manual assignments |

For an existing session, permissions are checked repeatedly within a 90-second
bound because Cassandra caches authorization. The test requires a real
Unauthorized response, not merely a changed system_auth row. Other eventually
checks also have explicit bounds. An already executing query is not cancelled.

A passing local matrix version requires the full Molecule lifecycle, idempotence,
15 access cases and 8 systemd secret-source cases, with no skipped tests. Six
passing versions give 90 access and 48 secret-source checks.
The isolated topology verifies normal paths and injected failures, not a proof
against every possible process/network failure ordering.

## Runtime Matrix

These are the source distributions. The systemd matrix copies each exact server
and its Java runtime into the Debian 12/systemd test image described above.

| Adapter | Server release | Test runtime |
|---|---|---|
| 2.2 | 2.2.19 | Java 8 native runtime, Cassandra 2.2 distribution, JNA 4.2.2 |
| 3.0 | 3.0.31 | Official Cassandra image |
| 3.11 | 3.11.18 | Official Cassandra image |
| 4.0 | 4.0.16 | Official Cassandra image |
| 4.1 | 4.1.10 | Official Cassandra image |
| 5.0 | 5.0.6 | Official Cassandra image |

`Dockerfile.cassandra22` copies the 2.2.19 server distribution/configuration
into the native Java 8 runtime of the 3.0.31 image and replaces JNA 4.0.0 with
4.2.2 for ARM JNI support. It does not retain Cassandra 3.0 server jars.
This validates the 2.2 server code on that runtime, not the unmodified x86-only
2.2 image on ARM. The Docker daemon architecture selects the native platform.

The 2.2 nodetool command uses an IPv4-mapped IPv6 loopback address for
[CASSANDRA-17581](https://issues.apache.org/jira/browse/CASSANDRA-17581).
Legacy JNDI URL parsing is not enabled.

## Evidence and Diagnosis

Matrix reports are ignored by Git and live in `.state/reports/`:

| File | Contents |
|---|---|
| summary.json | Latest recorded result for each version, including exit code, image, jar SHA-256, node releases and counts |
| VERSION/summary.json | One version's result |
| VERSION/results.xml | Pytest JUnit XML |
| VERSION/secrets.xml | Secret-source and systemd credential JUnit XML |
| VERSION/systemd.log | Cassandra systemd service journals |
| VERSION/molecule.log | Lifecycle, idempotence and test output |
| VERSION/containers.log | Both Cassandra nodes and LDAP logs |
| VERSION/previous-results.xml | Previous raw test result, when available |

A selective rerun preserves results for other versions, so aggregate entries
need not come from the same invocation. Compare jar hashes to the current
artifacts before reusing evidence. A build alone is not an e2e pass.
The matrix records run IDs, source commits, node versions and jar hashes for
local investigation. Release packaging does not read these reports, and its
manifest explicitly marks cluster E2E as local-only. Do not combine local reports
with CI-built jar hashes or claim they verify different binary files.
See [Releasing](../../RELEASING.md).
A failed bootstrap may have no results.xml; the exit code and logs remain
essential. Failed tests can affect later cases because this suite intentionally
exercises one user's lifecycle in order; diagnose the first failure first.

Standalone runs write `.state/current-results.xml` and
`.state/current-secrets.xml`, plus `.state/current-containers.log`, unless
CASSANDRA_VERSION selects another prefix. Systemd mode also writes
`.state/current-systemd.log`.
Expected failure-injection logs include LDAP errors, lock timeouts, policy
mismatches and QUORUM unavailability. Distinguish them from unexpected linkage
errors or failing JUnit cases. Raw logs can contain workspace paths and node
addresses; inspect/redact before sharing. Do not commit logs or rendered state.

The nonsecret `.state/mode` marker is mode 0644 so the systemd service user can
read it on native Linux filesystems. Secret files retain their restricted modes.
macOS Docker bind mounts can map file ownership differently; they are not a
substitute for testing Unix permissions on a Linux-native filesystem.

## Scope

OpenLDAP verifies direct membership through member/uniqueMember and directory
failures. The fixture uses group member attributes; it does not validate a real
AD memberOf deployment, AD disabling, nested/primary groups, LDAPS certificate
validation, multi-DC behavior, production-scale login load, mixed server-version
clusters or arbitrary JVM crashes during in-flight writes.
The plugin's limitations and recovery requirements are in
[ACCESS_SYNC.md](../../ACCESS_SYNC.md).
