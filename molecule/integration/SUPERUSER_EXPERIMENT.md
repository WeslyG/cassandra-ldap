# Bind-DN Cassandra Privilege Experiment

## Scope

The experiment compares startup creation of the LDAP service DN's Cassandra role.
The production Java sources and regular module jars are unchanged. Experimental
jars are built from Git commit `9a12806cd87fd1a9ace03a2487a87f819dfd3e72` in an
ignored source copy, using the two patches next to this document. They are not
release artifacts.

Each case uses a fresh two-node Cassandra cluster, OpenLDAP and disposable data
volumes. The nodes run as real systemd services. The bind identity is an ordinary
`inetOrgPerson`, `cn=svc_ldap,dc=example,dc=org`, not OpenLDAP's root DN. Its LDAP
ACL permits directory reads, but not reading password attributes. It belongs to
the readers group, whose initial policy permits SELECT on `app` and membership
in `reader_role`. The native internal actor is initially `cassandra`.

## Cases

| Variant | Initial state | Additional checks |
|---|---|---|
| baseline | Startup creates LOGIN=true, SUPERUSER=true | Read unmapped data; create a second SUPERUSER; verify group admission still applies |
| demoted | Original jar, then explicit ALTER ROLE SUPERUSER=false | Existing connection loses elevated access; rolling restart does not restore SUPERUSER |
| unprivileged | Patched startup creates LOGIN=true, SUPERUSER=false | Unmapped reads and SUPERUSER creation fail; normal policy access remains |
| absent | Patched startup omits bind-role creation | Role remains absent through all 15 access cases; later service login creates only an ordinary role |

All cases run the normal 15 access checks: first login, union of group mappings,
parallel logins, invalid credentials, membership changes, YAML changes, direct
permissions and role membership, manual-grant preservation, LDAP and replica
outages, policy mismatch, abandoned-lock rejection/recovery, background group
revocation and user deletion. The omitted-startup case does not authenticate the
service identity as a Cassandra client until after this lifecycle is complete.

Non-baseline cases then temporarily select the unprivileged service identity as
`cassandra_ldap_admin_user`. The probe records whether a new directory user can
be provisioned on both nodes. If provisioning succeeds, it also checks background
revocation and regrant. It restores the native internal actor, removes the service
identity from the permitted LDAP group and verifies that ordinary user access
continues while new service-user Cassandra logins are denied.

The separate secret-source suite is not part of this experiment. A systemd
service topology here is not a claim that every variant reran credential rotation
or ciphertext-corruption tests.

## Findings

The completed local matrix has 14 successful scenarios and 237 passing pytest
cases, with zero failures, errors or skips. Every scenario passes Molecule
idempotence and teardown; both actual server versions match the selected version.
All artifact and test-input hashes remain unchanged during their runs.

| Cassandra | Baseline | Demotion | Unprivileged startup | Omitted startup | Passing cases |
|---|---|---|---|---|---:|
| 4.1.10 | Pass | Pass | Pass | Pass | 67 |
| 4.0.16 | Not selected | Not selected | Pass | Pass | 34 |
| 5.0.6 | Not selected | Not selected | Pass | Pass | 34 |
| 3.11.18 | Not selected | Not selected | Pass | Pass | 34 |
| 3.0.31 | Not selected | Not selected | Pass | Pass | 34 |
| 2.2.19 | Not selected | Not selected | Pass | Pass | 34 |

Removing the bind identity's SUPERUSER flag does not prevent user creation,
grants, revokes, background reconciliation or rolling restarts in this matrix.
Omitting its startup Cassandra role also leaves these operations working; its
absence throughout the ordinary user's full lifecycle is confirmed separately on
each of the six server versions.

The baseline service identity can read the synthetic `restricted` keyspace even
though it is not in the LDAP policy, and can create another SUPERUSER role. Both
operations are rejected with Unauthorized after demotion and in the unprivileged
variant. Ordinary SELECT on `app` still succeeds. The restricted data is entirely
synthetic and exists only in the disposable cluster.

SUPERUSER does not bypass fresh LDAP authentication or the configured-group
admission requirement. The demonstrated excess privilege applies once the service
identity successfully authenticates and belongs to a permitted group. Removing
that group is not equivalent to removing the role's SUPERUSER flag.

The internal-actor probe also works on all six versions without that actor being
SUPERUSER, including provisioning on both nodes, background revocation and regrant.
The adapters parse statements, call `validate()` and execute them directly; they
do not call the client `authorize()`/`checkAccess()` step. Journal queries also
run in-process. The configured internal role name is therefore not an ordinary
authenticated network connection or a reliable authorization boundary for the
plugin's own mutations. This is distinct from granting those powers to an external
client using the bind password.

In-process trusted code does not authenticate with a Cassandra administrator's
password for each mutation. LDAP users' Cassandra roles likewise need no local
password: their client passwords are validated against LDAP. Neither observation
means that an external client can authenticate as the native administrator without
its password.

## Operational Interpretation

Automatic SUPERUSER creation for the LDAP bind DN is not needed by the tested
synchronization paths and gives a successfully authenticated service client powers
outside its LDAP-derived policy. LDAP directory-reader credentials and deliberate
Cassandra administrative identities should be separate responsibilities.

An implementation that changes only `createRole(bindDn, true)` to `false` affects
newly created roles. It does not demote existing SUPERUSER roles. The current
startup also leaves an explicitly demoted existing role unchanged, but deleting
that role allows the original bootstrap code to create it as SUPERUSER again.
Existing administrative dependencies require an explicit operator migration;
they must not be silently deleted or demoted.

This experiment does not remove Cassandra's ability to create administrators.
An existing administrator can explicitly create a SUPERUSER role or alter an
existing LDAP user's role. LDAP synchronization manages its owned memberships
and keyspace permissions, not the existing role's SUPERUSER flag.

The internal-actor probe is diagnostic, not a recommendation to point production
administration at the LDAP reader. Trusted internal execution and creator-related
side effects need their own design review. Retaining a working native recovery
administrator remains important.

## Evidence and Reproduction

See [runner commands](README.md#bind-role-privilege-experiment). The local
`superuser-experiment/summary.json` and per-case reports live under `.state/`.
They record the source commit, actual versions of both servers, artifact and test
input hashes, XML counts, privilege evidence and teardown status. Raw logs and
experimental jars stay ignored and are not uploaded or published.

An early exploratory run lacked directory-read ACLs for the ordinary bind
identity and failed before the intended privilege comparison. Its diagnostics
are retained separately as `baseline-before-ldap-acl`; it is not counted as a
successful case. The final matrix starts each case from fresh volumes with
explicit read-only directory ACLs.

The evidence covers OpenLDAP and single-DC, two-node clusters with controlled
maintenance. It does not establish behavior under AD-specific account controls,
TLS, multi-DC, production load or every crash/partition ordering. Revocation checks
allow cache/reconciliation delays rather than promising immediate cancellation
of existing requests.
