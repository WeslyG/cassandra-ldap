# Cluster Integration Tests

## Requirements and Isolation

The scenario name is `integration`; `matrix.json` selects the version adapters.
Run commands from the repository root on a host with Docker Compose v2, Bash,
Make, registry access and sufficient Docker resources. Allow at least 4 GB of
Docker memory for the test cluster; 6-8 GB is preferable when other services run.
A full matrix takes roughly 25-35 minutes, depending on pulls and machine speed.

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

Individual stages:

```sh
make build-all
make test-unit
make test-release
make check-docs
bash molecule/integration/run.sh matrix
```

Retest selected adapters without rebuilding jars:

```sh
bash molecule/integration/run.sh matrix 3.0 5.0
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

The matrix hashes the jar before running and checks it again afterward.
It records actual release versions from both servers, not just image tags.
Do not rebuild a jar while its cluster test is running.

## Unit Tests

`make test-unit` runs 10 TestNG tests using the 4.1 module as a classpath for
the shared code:

| Class | Count | Coverage |
|---|---:|---|
| AccessPolicyTest | 4 | Group union/deduplication, removal of one group, empty desired access, exact keyspace journal encoding |
| LDAPSecurityTest | 3 | LDAP filter escaping; empty and missing password rejection before opening LDAP |
| DistributedQueryTest | 3 | CQL quote/question-mark handling, set element escaping, missing bind parameters |

These tests do not start LDAP or Cassandra. They do not prove a running cluster
works or exhaustively test YAML parsing. Surefire XML reports are under
`cassandra-4.1/target/surefire-reports/`.

The Java module trees also contain embedded-cluster integration scaffolding.
It is not the supported end-to-end acceptance suite and is not run by
`make test-unit`; do not equate this target with an unrestricted `mvn test`.
The Docker/Molecule scenario is the real-cluster acceptance path.

`make check-docs` runs in the same runner without mounting the Docker socket.
It checks README YAML against the example file, Java defaults, Maven/matrix
versions, local documentation links, 10 unit annotations and collection of all
15 pytest cases without opening database or LDAP connections.

## Behavioral Tests

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

A passing version requires the full Molecule lifecycle, idempotence, exactly 15
cases and no skipped tests. Six passing versions give 90 behavioral checks.
The isolated topology verifies normal paths and injected failures, not a proof
against every possible process/network failure ordering.

## Runtime Matrix

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
| VERSION/molecule.log | Lifecycle, idempotence and test output |
| VERSION/containers.log | Both Cassandra nodes and LDAP logs |
| VERSION/previous-results.xml | Previous raw test result, when available |

A selective rerun preserves results for other versions, so aggregate entries
need not come from the same invocation. Compare jar hashes to the current
artifacts before reusing evidence. A build alone is not an e2e pass.
A release additionally requires a common run ID from one full invocation, the
same clean source commit, both actual node versions, idempotence and teardown.
The matrix records this provenance; selective development runs do not satisfy
the release gate. See [Releasing](../../RELEASING.md).
A failed bootstrap may have no results.xml; the exit code and logs remain
essential. Failed tests can affect later cases because this suite intentionally
exercises one user's lifecycle in order; diagnose the first failure first.

Standalone runs write `.state/current-results.xml` and
`.state/current-containers.log` unless CASSANDRA_VERSION selects another prefix.
Expected failure-injection logs include LDAP errors, lock timeouts, policy
mismatches and QUORUM unavailability. Distinguish them from unexpected linkage
errors or failing JUnit cases. Raw logs can contain workspace paths and node
addresses; inspect/redact before sharing. Do not commit logs or rendered state.

## Scope

OpenLDAP verifies direct membership through member/uniqueMember and directory
failures. The fixture uses group member attributes; it does not validate a real
AD memberOf deployment, AD disabling, nested/primary groups, LDAPS certificate
validation, multi-DC behavior, production-scale login load, mixed server-version
clusters or arbitrary JVM crashes during in-flight writes.
The plugin's limitations and recovery requirements are in
[ACCESS_SYNC.md](../../ACCESS_SYNC.md).
