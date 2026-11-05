# Changelog

Each release lists changes relative to its predecessor. Installation, configuration
and operational limits are documented in the linked guides, not repeated here.

## 1.4.0 - 2026-11-05

### Security

- Stop creating a Cassandra SUPERUSER role for `ldap_service_dn` on all six adapters.
  LDAP bind requires directory access, not a corresponding Cassandra role.
- Preserve existing bind-DN roles, privileges and operator-created administrators.
  LDAP user roles created on successful login remain non-superusers by default.

### Testing and Releases

- Add permanent cluster regressions for absent bind roles and preservation of
  existing roles across restarts, alongside the access and systemd-secret suites.
- Add a reproducible six-version privilege experiment and its findings.
- Generate concise GitHub release notes from this version's changelog entry and
  include the changelog in the download bundle.

### Upgrade

Existing bind-DN SUPERUSER roles are **not automatically demoted**. Before rollout,
retain and verify an independent native administrator, audit the bind identity's
Cassandra access, and explicitly remove unnecessary administrative privileges.
If that identity was your Cassandra administrator, provision its replacement first.
Follow [bind-identity access review](ACCESS_SYNC.md#bind-identity-access-review)
and the [planned-maintenance protocol](ACCESS_SYNC.md#planned-maintenance).

## 1.3.0 - 2026-11-05

### Added

- LDAP bind passwords from process ENV, UTF-8 secret files and systemd credentials,
  with exclusive source selection and startup failure for missing or invalid secrets.
- Real systemd encrypted-credential tests, including damaged ciphertext and rotation.

### Testing and Releases

- Keep cluster E2E local; release CI runs builds, unit, packaging and documentation checks.
- Coordinate controlled test restarts with the maintenance lock; document production
  restart and abandoned-owner recovery requirements without claiming a worker drain.

## 1.2.0 - 2026-11-05

### Added

- Unified LDAP access synchronization across Cassandra 2.2, 3.0, 3.11, 4.0, 4.1 and 5.0.
- YAML direct-group mappings to multiple role memberships and keyspace permissions.
- Managed grants and revocations with a shared policy, LWT coordination and ownership
  journal, preserving unrelated manual assignments.
- Two-node/OpenLDAP acceptance infrastructure and verified release bundles with
  six shaded adapters, checksums and a source/artifact manifest.
