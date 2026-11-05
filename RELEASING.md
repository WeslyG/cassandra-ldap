# GitHub Releases

## Assets

A stable release uses one version for the Maven parent, shared base and all six
adapters. Root/module versions, matrix artifact versions and the tag must agree.

| Download | Purpose |
|---|---|
| Six cassandra-ldap-SERVER-VERSION.jar files | Individual shaded adapters; install only one on a node |
| cassandra-ldap-VERSION.zip | All jars, YAML example, journal schema, secret guide, license, installation instructions and internal checksums |
| release-manifest.json | Source commit, exact built jar hashes and fast verification scope |
| SHA256SUMS | SHA-256 for every jar, ZIP and manifest |

These are nine downloadable assets. Raw logs, XML reports, workstation paths,
caches and rendered deployment secrets are not release assets. The example
password is REPLACE_WITH_SECRET, not a bind credential.

## Local Testing

Cluster E2E runs locally, not in GitHub Actions or CircleCI. For runtime changes
run the full two-node/OpenLDAP matrix with real systemd credentials:

```sh
make integration-systemd
```

Use a trusted Docker host and disposable credentials. The six versions run
sequentially. Inspect actual node versions, jar hashes, 15 access cases and
8 secret-source cases per version, idempotence and teardown; require no skips.
Reports remain ignored under molecule/integration/.state/reports/.

A CI rebuild can produce different bytes from a local build. Local reports are
not attached to CI artifacts or represented as proof that those exact published
bytes passed E2E. Investigate local failures before deployment; a successful
release build alone does not establish running-cluster correctness.

## Prepare and Publish

1. Align versions and documentation, run appropriate local E2E and fast checks.
2. Commit the sources. Releases require a clean working tree.
3. Create an annotated stable tag on that exact commit:

```sh
git tag -a v1.3.0 -m "Cassandra LDAP Authenticator v1.3.0"
git push origin master
git push origin v1.3.0
```

4. Follow the tag-triggered workflow through verification and publication. CI
   runs `make verify-fast`: builds all six adapters and runs Java unit tests,
   packaging tests and documentation checks. It does not start Cassandra, LDAP
   or systemd clusters.
5. Packaging checks the tagged source and built jars; publication verifies the
   exact uploaded byte set before making the release Latest.

For local preparation of a tagged download set:

```sh
make verify-fast
RELEASE_TAG=v1.3.0 make release-package
```

Output is ignored under dist/v1.3.0/. Existing output is not overwritten.
Never replace published artifacts or repoint a published release tag.

## Verification Gates

Packaging rejects inconsistent versions, missing adapters/jars, a tag not
pointing to HEAD, dirty source trees, missing/failed/skipped/stale Java unit
results, missing plugin classes and wrong embedded Maven versions. The 18 Java
unit tests must run after jar packaging. Server dependencies such as Cassandra
CQL classes, Guava and SnakeYAML must not be bundled.

The 16 packaging unit tests use synthetic temporary repositories and jars. They
check public asset contents/checksums, readable output modes, version/tag/source
guards, jar structure, unit reports, output overwrite protection and independence
from local E2E reports. Local E2E state is neither read nor required by packaging.

Five additional maintenance-helper unit tests verify exclusive reservation,
lost CAS reply resolution, exception cleanup and refusal to clear another owner.
These use a fake session and do not start services.

Manifest schema 2 marks cluster E2E as `not_run_by_release_pipeline` with
`execution: local_only`. It contains no cluster pass counters, invocation IDs,
node images or implied systemd verification. Release notes describe that scope
explicitly. The manifest is traceability, not a signed supply-chain attestation.

## Workflow and Permissions

[Verified Release](.github/workflows/release.yml) runs on v* tag pushes and can
be dispatched with an existing stable tag to retry an unpublished candidate.
Checkout is pinned by commit SHA and does not persist credentials in sources.
Java and Python/Ansible checks execute in their respective build/test containers;
the CI check containers do not receive the Docker socket.

The verification job has read-only repository permissions. An immutable workflow
artifact transfers only the prepared download set to a separate publication job.
Repository contents write permission and GH_TOKEN are scoped to publication.
Official checkout/upload/download actions are pinned by SHA.

Publication creates or resumes a draft, uploads allowlisted files, checks the
remote asset set, downloads it again and verifies every byte against checksums.
Only then is the draft published as Latest. Published releases are not overwritten.
A partial draft accepts only missing files, never clobbers existing ones, and
requires them all to match the prepared checksums. If rebuilt bytes differ,
explicitly discard only the unpublished draft before retrying.

[Testing](molecule/integration/README.md) documents local topology, commands,
coverage, the Cassandra 2.2 runtime qualification and untested AD/TLS/multi-DC cases.
