# Verified GitHub Releases

## Assets

A stable release has one version for the Maven parent, shared base and all six
adapters. Root/module versions, matrix artifact versions and the tag must agree.
Each jar name contains both its Cassandra server version and plugin version.

| Download | Purpose |
|---|---|
| Six cassandra-ldap-SERVER-VERSION.jar files | Individual shaded adapters; install only one on a node |
| cassandra-ldap-VERSION.zip | Complete bundle with all jars, YAML example, journal schema, secret deployment guide, license, installation instructions and internal checksums |
| release-manifest.json | Source commit, common e2e invocation ID, test counts, node versions/images/platforms and exact tested jar hashes |
| SHA256SUMS | SHA-256 for every jar, ZIP and manifest |

These are nine downloadable assets. Release notes provide direct downloads,
compatibility, verification scope and operational warnings. Raw logs, XML reports,
workstation paths, caches and rendered deployment secrets are not assets. The
example password is REPLACE_WITH_SECRET, not a bind credential.

## Prepare and Publish

1. Update Maven versions, matrix plugin versions, the default Compose jar path
   and README compatibility table. Run documentation and packaging checks.
2. Commit the sources. Releases require a clean working tree.
3. Create an annotated stable tag on that exact commit:

```sh
git tag -a v1.3.0 -m "Cassandra LDAP Authenticator v1.3.0"
```

4. Push the release commit and tag to the intended repository:

```sh
git push origin master
git push origin v1.3.0
```

5. Follow the tag-triggered workflow through verification and publication. It
   builds all jars, runs unit/packaging/documentation checks, tests the full
   six-version systemd matrix from the clean tagged commit and packages exactly
   those tested jars. The release becomes Latest only after remote byte checks.

Local preparation uses the same gates and is optional when CI performs the full
sequence. From the clean tagged commit run:

```sh
make integration-all
RELEASE_TAG=v1.3.0 make release-package
```

Output is ignored by Git under dist/v1.3.0/. Existing output is not overwritten.
Never replace published artifacts or repoint a published release tag. Local
evidence is not substituted for the fresh CI run. Rebuilding can change jar
hashes; evidence must match the files being released. ZIP entries use the commit
timestamp and fixed permissions, without local filesystem ownership metadata.

## Verification Gates

Packaging rejects inconsistent versions, a tag not pointing to HEAD, dirty source
trees, stale unit results, mixed e2e invocation IDs, incomplete lifecycles,
failed/skipped cases, wrong actual node versions and modified jars. It checks
shared plugin classes and embedded Maven metadata, and rejects artifacts bundling
Cassandra CQL classes, Guava or SnakeYAML.

All six adapters must pass 15/15 access cases and 8/8 secret-source cases under
real systemd in one full matrix invocation from the clean tagged commit, with
matching hashes, idempotence and teardown. The 18 Java unit
tests must run after jar packaging and before the matrix. Selective reruns help
development but cannot combine unrelated results into release evidence.

```sh
make test-release
make check-docs
```

The 12 packaging unit tests use synthetic temporary repositories, jars and reports.
They verify successful packaging/checksums and rejection of changed jars, skipped
e2e, wrong node versions, mixed runs, dirty/different commits, wrong versions,
stale unit reports, missing XML and absent/failed systemd secret tests. These
12 packaging tests are separate from the 18 Java tests, 90 live-cluster access
checks and 48 secret-source checks described in [the integration guide](molecule/integration/README.md).

## Workflow and Permissions

[Verified Release](.github/workflows/release.yml) runs on v* tag pushes and can
be dispatched with an existing stable tag to retry an unpublished candidate.
Checkout is pinned by commit SHA and does not persist credentials in the source
mounted into test containers. The Ubuntu runner supplies Docker; Java and
Python/Ansible/Molecule execute in their respective pinned build/test containers.

Verification runs in a read-only-permission job. An immutable workflow artifact
transfers only the prepared download set to a separate publication job, with no
Docker test runner. Official checkout/upload/download actions are pinned by SHA.
Repository contents write permission is scoped to that publication job. GH_TOKEN
is exposed only to its publication step; no personal access token is stored in
source or passed into the Docker test runner.

Publication creates or resumes a draft, uploads the allowlisted files, checks
the exact remote asset set, downloads it again and verifies every byte against
the prepared checksums. Only then is the draft published as Latest. Published
releases are not overwritten. On failure inspect the draft/workflow before
retrying; do not weaken verification guards.
Retrying a partial draft uploads only missing assets, never clobbers existing
files, and requires them all to match the prepared checksums. If a full rebuild
changes bytes, explicitly discard only the unpublished draft before retrying.

The manifest supplies traceability, not a signed supply-chain attestation.
[Testing](molecule/integration/README.md) documents OpenLDAP/two-node coverage,
the Cassandra 2.2 runtime qualification, and untested AD/TLS/multi-DC cases.
