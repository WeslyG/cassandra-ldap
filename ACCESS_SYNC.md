# Cassandra 4.1 access synchronization

Provision a dedicated `ldap_auth` keyspace using NetworkTopologyStrategy with
replication appropriate for every DC, then apply `conf/access-sync-schema.cql`
before starting the new plugin. Only database administrators may access it.
Configure `auth_write_consistency_level: QUORUM` (or ALL) in cassandra.yaml.
Repair system_auth and ldap_auth after changing replication.

The plugin records direct memberships and keyspace permissions it adds. Existing
manual assignments are preserved and are not adopted automatically. An assignment
must not be managed both manually and through LDAP. To migrate previous plugin
assignments, audit them and seed the ownership journal before enabling sync;
otherwise they will be treated as manual. Permission journal entries use
`PERMISSION:BASE64_UTF8_KEYSPACE`. Do not put passwords in these tables.

On authentication, LDAP credentials are checked again. Groups are read again
under a cluster-wide LWT lock; the ownership journal is written before grants.
Revokes precede grants, and failed operations reject the login. The journal is
retained on partial failure so the next reconciliation can retry. A daemon runs
every 60 seconds (first run after 10 seconds) over journaled users. Removing all
groups or deleting a user therefore revokes journaled grants without a new login.
LDAP failures leave rights unchanged and are logged. Only direct group membership
is supported; nested AD groups and AD primary-group membership are not expanded.
Disabled AD accounts are rejected explicitly. Their journaled grants currently
require operator revocation: background lookup treats disabled-account errors
as failures rather than as proof of an empty group set.

The first node registers a deterministic policy fingerprint. Other policies are
rejected, preventing mixed configurations from issuing competing grants. For a
policy change, activate the new fingerprint with a conditional update of the
coordinator's `policy` column using `IF owner=null`. Retry if a sync is active.
Old-policy nodes then reject LDAP synchronization. Deploy identical YAML and
restart nodes in rolling order, waiting for each node to become ready. Keep a
native database administrator available during this transition. The integration
harness demonstrates this procedure in `change_policy`.
The fingerprint excludes the service password so secret rotation is independent.

The global lock intentionally has no TTL. A crashed or timed-out owner blocks
later LDAP synchronization. Inspect `SELECT * FROM ldap_auth.coordinator`, stop
the previous owner process (all plugin nodes if ownership is uncertain), then
clear `owner` with a conditional update matching the observed UUID. Never clear
a live owner's lock. Automatic expiry would permit a paused JVM to resume writes
concurrently with another owner. Local database administration remains available.

Revocation is not instantaneous: LDAP replication, the reconciliation interval,
the number of users, and Cassandra permission/role caches contribute to delay.
An already running query is not cancelled. For urgent removal, perform the revoke
as an administrator and invalidate the relevant caches on every node. Open
connections must be included in deployment validation.

This implementation requires two-node integration validation before production.
Do not interpret a successful package build as evidence of distributed correctness.
