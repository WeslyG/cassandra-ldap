# Maintainer Guide

Read this file before changing authentication, permissions, configuration or the
test infrastructure. It describes the working architecture and verification
contract, not a changelog.

## Project Map

- `base`: typed YAML configuration, JNDI LDAP lookup, password handling, shared
  role/permission synchronization, distributed query binding and ownership journal.
- `base/.../auth/AbstractSystemAuthRoles.java`: common native authorization
  behavior, QUORUM reads and legacy mutation mirroring.
- `base/.../auth/LdapAccessSync.java`: policy fingerprint, global LWT lock,
  write-ahead ownership, foreground/background reconciliation.
- `cassandra-2.2`, `3.0`, `3.11`, `4.0`, `4.1`, `5.0`: Cassandra API
  adapters and ServiceLoader descriptors. Only one adapter jar belongs on a node.
- `conf/ldap.yaml`: production-shaped example with a secret placeholder.
- `conf/access-sync-schema.cql`: operator-provisioned journal schema.
- `molecule/integration`: shared two-node/OpenLDAP acceptance scenario and matrix.
- `README.adoc`: installation/configuration; `SECRET_HANDLING.md`: secret sources,
  systemd/Ansible deployment and rotation; `ACCESS_SYNC.md`: operational rules;
  `molecule/integration/README.md`: test commands, coverage and limitations.
- `RELEASING.md`, `scripts/package_release.py` and `.github/workflows/release.yml`:
  clean-tag, fast verification gates and nine public release assets.

The shared base compiles against provided Cassandra 3.0.31 and Java 8 bytecode.
Do not introduce newer JDK APIs into it. Cassandra API differences belong in the
version adapters. SnakeYAML is provided by the server; SafeConstructor must work
with both 1.x and 2.x. Do not shade Cassandra, Guava or another YAML runtime.

## Security Invariants

- Reject empty/missing passwords and wrong native passwords.
- Resolve exactly one explicit bind-secret source (inline, ENV, file or systemd
  credential). Never trim passwords, fall back to another source, log secret
  values/parser excerpts or include source selectors in policy fingerprints.
- Refresh LDAP credentials on every login; caches must not bypass LDAP checks.
- Escape LDAP filter values and CQL literals/identifiers. Never turn a username
  into a raw LDAP filter or interpolate an unescaped DN.
- Resolve one directory identity and union direct groups; missing configured
  group objects may be skipped, other lookup failures must not become empty groups.
- Calculate desired access again under the shared lock. Journal ownership before
  grants, revoke stale owned entries before additions, and fail the login on errors.
- Preserve manual assignments; never adopt existing grants silently.
- Keep mapped roles/keyspaces operator-created. Ordinary LDAP roles are LOGIN=true
  and SUPERUSER=false. Never create or elevate a Cassandra role for the directory
  bind identity at startup. Preserve existing roles and require explicit operator
  review of unnecessary privileges; do not silently demote an administrator.
- Do not add a TTL to the global lock or clear a live owner's lock. Recovery must
  stop uncertain writers and use a conditional owner update.
- Require consistent policy fingerprints across nodes; preserve safe transitions.
- Keep journal reads/writes at QUORUM and resolve uncertain CAS ownership before
  auth writes. Modern native auth writes require QUORUM/ALL; legacy adapters
  mirror validated native changes at QUORUM.
- Preserve a working native administrator during LDAP/cluster failures.
- Do not promise instantaneous revocation or cancellation of running queries.
  AD-disabled-account background revocation needs operator intervention;
  nested/primary groups are not expanded.

## Commands and Verification

Run Python/Ansible/Molecule in the pinned ansible-infra runner, not host Python.
Use the Java build container for Maven. Docker socket access is highly privileged;
use only trusted code and disposable credentials.

```sh
make build-all
make verify-fast
make test-unit
make test-release
make check-docs
make integration-all
make integration-systemd
LDAP_TEST_SYSTEMD=true bash molecule/integration/run.sh matrix 3.0 5.0
```

`test-unit` selects 18 shared-code tests through the 4.1 classpath, not the embedded
Java integration scaffolding. Maven packaging must force jar recreation so shaded
outputs cannot retain stale classes. Never rebuild an artifact during its e2e run.

Cluster E2E is local-only. Never add it to GitHub Actions or CircleCI; CI uses
`make verify-fast` without a Docker socket in check containers. For runtime/shared-code
changes run the full six-version matrix locally. For a version-only
adapter change run at least its real-cluster scenario plus unit tests, and explain
what was not rerun. Require idempotence, 15/15 access, 3/3 bind-role regressions
and 8/8 systemd secret cases,
zero skips, both actual server
versions and matching jar hashes. Selective reruns preserve other summaries:
check artifact hashes instead of treating the aggregate as one fresh invocation.
Do not claim all cases are proven by compilation or unit tests alone.

Secret-source changes also require `integration-systemd`: both Cassandra nodes
run as real systemd services with encrypted credentials in a disposable privileged
container. Never substitute a fake CREDENTIALS_DIRECTORY for that verification.
The boot script uses `mount --make-rshared /` inside the private container mount
namespace only. Never apply it to the host or mount host credential/cgroup trees.

Use the harness maintenance context around planned node/service restarts. It
reserves only an idle coordinator, resolves uncertain CAS replies using SERIAL,
and releases only its own controller UUID. Never clear an orphaned plugin owner
to make a test pass. The plugin has no automatic graceful worker drain; document
the production restart/lock-recovery limitation separately from test coordination.

Clusters share a fixed project/network/runner name and must run sequentially.
The local bind-role privilege experiment uses `scripts/build_superuser_experiment.sh`
and `run.sh superuser`. It builds patched snapshots of its pinned comparative
baseline into ignored state,
not regular module targets. Never publish these experimental jars. Keep its
privilege probes separate from the normal 3-bind/15-access/8-secret acceptance counts;
record internal DBA behavior rather than assuming trusted statements enforce
external-client authorization. Do not run it alongside the normal matrix.
Seed auth RF=2 precedes node 2 joining; perform full repair before enabling the
plugin. Readiness includes native role mutations. Restarts must be rolling.
Permission-cache tests must wait for an actual Unauthorized response. Remember
that pytest.raises failures derive from BaseException, not Exception.

The 2.2 test image uses native Java 8, exact 2.2 server jars and JNA 4.2.2 for ARM;
its nodetool uses an IPv4-mapped IPv6 loopback address. Do not substitute 3.0 server
binaries or weaken JNDI parsing to make the test pass. OpenLDAP is not Samba AD.
Document untested AD, TLS, multi-DC, load and crash-ordering scenarios honestly.

Reports, generated YAML, Maven caches and jars stay ignored. Retain local test
evidence when useful but do not commit workstation paths or raw container logs.
When changing docs, describe the present system directly and verify commands,
defaults, examples and local links against code. Do not write release notes
inside installation instructions.

## Repository Hygiene

Use only synthetic example.org identities and disposable test passwords in
fixtures. Never commit real bind passwords, rendered Ansible/Vault output,
private keys, tokens, internal addresses or personal workstation paths. Preserve
LICENSE and required attribution. Public image/package names are technical
dependencies, not credentials.

Before a commit inspect the complete staged diff, run `git diff --check`, scan
tracked/new content and relevant Git history for secrets with redacted output,
and verify generated artifacts are not staged. Do not rewrite history merely
to remove public author metadata. If a real secret is found in history, stop
publication and arrange rotation and an explicit history-cleanup plan.
Push only to the user's intended remote/branch, never the upstream repository
by assumption. Never commit an unrelated user's change without inspecting it.

## Releases

Keep all Maven and matrix artifact versions aligned with the stable release tag.
Maintain a dated CHANGELOG.md entry per version; release notes are generated from
that entry, not a repeated product overview. Put migrations in the version entry
and keep installation/operations documentation focused on current behavior.
Run appropriate E2E locally and investigate failures. Release CI builds all jars
and runs only unit, packaging and documentation checks. Packaging requires a clean
tagged source, correct jar structure/versions and a passing fresh Java unit report;
it neither requires nor imports local E2E reports. Do not claim that CI-built bytes
passed local E2E or fabricate cluster pass counters in manifests/release notes.
The package must not contain raw logs, XML, workstation paths or real secrets.
Never repoint a published tag or replace published assets. GitHub publication
runs separately from Docker verification with contents-write permission scoped
only to the publish job, and checks downloaded asset bytes before publishing.
