# Access Synchronization Operations

## Provisioning

Keep an existing native superuser available independently of LDAP. Give
system_auth and ldap_auth suitable NetworkTopologyStrategy replication in every
DC, with enough replicas/live nodes for QUORUM. The following is an example for
a three-node DC named dc1, not a universal replication setting:

```sql
ALTER KEYSPACE system_auth WITH replication = {'class':'NetworkTopologyStrategy','dc1':'3'};
CREATE KEYSPACE ldap_auth WITH replication = {'class':'NetworkTopologyStrategy','dc1':'3'};
```

Replace the DC/RF with the actual topology. Apply
[conf/access-sync-schema.cql](conf/access-sync-schema.cql) as an administrator,
and repair keyspaces after replication changes. The schema file creates tables,
not the keyspace. Do not give LDAP-managed users write access to ldap_auth.
Create mapped roles/keyspaces before enabling the plugin.

The service bind identity needs directory-read access, not a Cassandra role.
Startup neither creates nor elevates a Cassandra role named after the bind DN.
Protect that directory identity and its password. Existing Cassandra roles are
not deleted, demoted or otherwise changed by startup.
Ordinary LDAP client users get DN-named LOGIN=true, SUPERUSER=false roles
without native password hashes. Mapped permission-container roles are
operator-created and may have LOGIN=false.

On 4.1 and 5.0 configure auth_write_consistency_level as QUORUM or ALL; a weaker
value prevents synchronization startup. QUORUM auth reads are also recommended.
Do not add unsupported settings on 2.2, 3.0, 3.11 or 4.0. Those adapters execute
Cassandra's validated native authorization statements, then repeat the relevant
auth-table and index mutations at QUORUM before releasing the synchronization
lock. Shared journal/assignment reads and writes use QUORUM on every adapter.

## Bind Identity Access Review

Keep LDAP reader credentials separate from deliberate Cassandra administrators.
Before deployment, verify an independent native superuser connection. If the bind
identity is also used for Cassandra administration, provision and verify its
replacement before removing any privileges.

Use that independent administrator to audit the actual DN-named role, including
inherited roles and manually assigned permissions. For a synthetic example DN:

```sql
LIST ROLES OF "cn=ldap-reader,dc=example,dc=org";
LIST ALL PERMISSIONS OF "cn=ldap-reader,dc=example,dc=org";
ALTER ROLE "cn=ldap-reader,dc=example,dc=org" WITH SUPERUSER = false;
```

Run ALTER only if the audited role exists and its elevation is unnecessary.
Inherited superuser memberships must be reviewed separately: SUPERUSER=false
does not remove them. Revoking existing manual permissions or dropping the role
also requires an explicit operator decision. If this is strictly a directory
reader, LOGIN=false can prevent new Cassandra client logins without disabling
LDAP bind. Do not disable the configured internal Cassandra actor or your only
working administrator.

Use the [maintenance protocol](#planned-maintenance) for planned restarts.
Authorization caches can delay demotion for existing connections, and disabling
LOGIN does not terminate an already authenticated session. Close affected client
connections when the access review requires that guarantee.

The plugin's internal mutation path is trusted in-process code, not a password-
authenticated administrator connection. Its configured actor name is not a
client-permission boundary: statements are validated and executed without the
external-client authorization step. LDAP credential/group checks, safe query
construction and reconciliation policy enforce the plugin's access contract.

## Journal and Ownership

The operator-provisioned tables are:

| Table | Purpose |
|---|---|
| ldap_auth.coordinator | Singleton id='global' with active policy fingerprint and optional owner UUID |
| ldap_auth.assignments | Per-user-role sets of owned memberships and direct keyspace permissions |

Permission entries are `PERMISSION:BASE64_UTF8_KEYSPACE`; the base64 value is
encoding, not encryption. DNs/role names identify users, so restrict access to
these tables and their backups. Never store passwords there.

The plugin owns only assignments it adds or assignments already recorded in its
journal. A manually existing desired grant is preserved without being adopted.
If LDAP and an operator manage the same exact assignment, ownership cannot be
inferred from Cassandra's grant alone. Choose one owner for each assignment.

To adopt existing access, audit actual grants and seed only the intended
ownership entries while synchronization is stopped. Preserve unrelated manual
grants. Do not erase the journal or coordinator to force a policy change:
doing so loses ownership or locking information.

## Reconciliation

After LDAP credential verification, the plugin checks the policy and acquires
a global, cluster-wide LWT lock. It re-reads direct group membership under that
lock, unions matching mappings, validates referenced roles/keyspaces and records
ownership before granting anything. It revokes stale owned access before adding
desired grants. A failure rejects the login and leaves journal information for
a later retry; synchronization is not one atomic transaction across all auth rows.

Lock acquisition waits for up to eight seconds with short randomized backoff.
An uncertain CAS result is resolved with a SERIAL owner read before auth writes.
The lock is shared by all users and plugin nodes, so synchronization is serialized;
login throughput and background work must be load-tested for the real deployment.

Each node schedules reconciliation over journaled users with an initial delay
of 10 seconds and a fixed delay of 60 seconds after each pass. Runtime of the pass
and lock contention add to the delay. Removing a user's final group or deleting
the LDAP user therefore revokes owned grants without another successful login.
Native/manual grants are retained.

A nonexistent configured group object is skipped. Other directory failures are
not treated as proof of lost membership: LDAP outages preserve permissions,
are logged, and reject new LDAP authentication. Native administration remains
available when the required Cassandra replicas are reachable.

Direct memberOf and group member/uniqueMember lookups are supported. Nested and
AD primary groups are not expanded. Disabled AD accounts are denied, but their
background lookup raises an error rather than returning an authoritative empty
group set. Their owned grants require operator revocation; do not assume an AD
disable operation alone revokes permissions from an existing CQL session.

## Policy Changes

The active policy is a deterministic SHA-256 fingerprint, including LDAP URI,
filter, service DN, normalized group mappings and expanded target permissions.
The bind password is excluded so secret rotation does not change the policy.
All nodes must use the same logical policy.

A node with another fingerprint rejects synchronization. A startup mismatch
reports its candidate fingerprint in the log. Obtain that fingerprint from the
candidate configuration using the same plugin/server version; do not hash raw
YAML bytes or reuse the integration fixture's hard-coded assumptions.

1. Retain native administrator access and stage the candidate YAML on one node.
   A mismatching candidate fails synchronization startup and reports its fingerprint.
2. Read the current coordinator policy/owner using a native administrator.
3. Reserve an idle coordinator with a fresh maintenance UUID, conditional on
   the observed old policy. Activate the candidate conditional on that same
   maintenance owner and old policy. Inspect both applied results.
4. Install identical YAML on all nodes and restart them in rolling order,
   waiting for role operations to be ready. Restart the candidate node too.
5. Release only the maintenance UUID after all nodes recover. Verify new and
   existing-session access, owned revokes, preserved manual grants
   and background reconciliation.

Illustrative CQL (replace the fingerprint placeholders and use the same freshly
generated UUID for all three statements; release only after the rolling restart):

```sql
SELECT * FROM ldap_auth.coordinator WHERE id='global';
UPDATE ldap_auth.coordinator
SET owner=<fresh-maintenance-uuid>
WHERE id='global'
IF owner=null AND policy='<observed-current-fingerprint>';
UPDATE ldap_auth.coordinator
SET policy='<candidate-fingerprint>'
WHERE id='global'
IF owner=<fresh-maintenance-uuid> AND policy='<observed-current-fingerprint>';
-- Restart/recover all nodes before releasing the maintenance owner.
UPDATE ldap_auth.coordinator
SET owner=null
WHERE id='global'
IF owner=<fresh-maintenance-uuid>;
```

Use appropriate QUORUM/SERIAL consistency for administration. An in-progress
sync blocks activation. Nodes with the old policy reject LDAP synchronization
after activation instead of racing to re-grant old access. The test harness's
change_policy function demonstrates a fixture policy transition, not a
general-purpose production fingerprint tool.

## Planned Maintenance

The Java background worker has no coordinated stop/drain API. A node or service
restart during synchronization can interrupt a writer or its QUORUM unlock and
leave a persistent owner. A rolling restart by itself does not prevent this.

Before planned restarts, use a native administrator to reserve the coordinator
with a fresh controller UUID using LWT `IF owner=null`. Proceed only after an
applied result, or a SERIAL read proving ownership after an uncertain CAS reply.
An existing owner must finish or undergo the separate recovery procedure; never
overwrite it. Keep this reservation through the restart window, then release it
conditionally with `IF owner=<your-maintenance-uuid>` after recovery.

This pauses LDAP synchronization and can reject new LDAP logins while held;
native administration remains available. It is an explicit operator procedure,
not automatic crash recovery. Preserve the controller UUID and do not clear
someone else's owner if a maintenance command fails.

## Lock Recovery

The global lock deliberately has no TTL. A process crash or an uncertain release
can leave an owner recorded, blocking subsequent LDAP synchronization. Automatic
expiration would let a paused process resume writes after another owner acquires
the same lock.

1. Inspect the owner UUID and logs. Do not clear a lock just because it is old.
2. Stop the previous writer process. If its identity is uncertain, stop every
   plugin-enabled Cassandra process that might still perform reconciliation.
3. Bring sufficient nodes up with native PasswordAuthenticator,
   CassandraRoleManager and CassandraAuthorizer, without LDAP synchronization
   workers, if necessary to obtain a recovery quorum and native admin connection.
4. Clear only the exact observed UUID with a conditional update and inspect
   the applied result. Never issue an unconditional owner=null update.
5. Restore the plugin/configuration, roll nodes and verify reconciliation.

For example, substitute the observed UUID in this statement:

```sql
UPDATE ldap_auth.coordinator
SET owner=null
WHERE id='global'
IF owner=11111111-1111-1111-1111-111111111111;
```

The UUID in the example is synthetic, not a reusable recovery token. Do not
clear a live owner's lock. Ownership uncertainty is an operational incident,
not permission to start a competing writer.

## Revocation and Validation

Cassandra permission/role caches, directory replication, reconciliation interval,
number of users and lock contention contribute to revocation latency. A running
query is not cancelled. For urgent revocation perform the administrative revoke
and invalidate relevant caches on every node, and verify existing connections.

[The integration guide](molecule/integration/README.md) documents the two-node
OpenLDAP matrix, actual permission checks, idempotence, jar hashes and reports.
Those tests do not validate AD-specific behavior, multi-DC operation, TLS setup,
production load or every in-flight crash/network ordering.
