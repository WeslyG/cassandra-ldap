package com.instaclustr.cassandra.ldap.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import com.instaclustr.cassandra.ldap.conf.*;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Cluster-wide serialization and write-ahead ownership journal. Schema is provisioned by operators. */
final class Cassandra41AccessSync
{
    private static final Logger logger = LoggerFactory.getLogger(Cassandra41AccessSync.class);
    private final Cassandra41SystemAuthRoles roles;
    private boolean started;

    Cassandra41AccessSync(Cassandra41SystemAuthRoles roles) { this.roles = roles; }

    synchronized void start(LdapConfiguration config)
    {
        if (started) return;
        if (org.apache.cassandra.auth.CassandraAuthorizer.authWriteConsistencyLevel() != ConsistencyLevel.QUORUM
            && org.apache.cassandra.auth.CassandraAuthorizer.authWriteConsistencyLevel() != ConsistencyLevel.ALL)
            throw new IllegalStateException("LDAP synchronization requires auth_write_consistency_level QUORUM or ALL");
        policy(config);
        ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "ldap-access-reconciliation");
            thread.setDaemon(true);
            return thread;
        });
        worker.scheduleWithFixedDelay(() -> {
            try
            {
                for (UntypedResultSet.Row row : QueryProcessor.execute("SELECT user_role FROM ldap_auth.assignments", ConsistencyLevel.QUORUM))
                {
                    try { sync(row.getString("user_role"), config); }
                    catch (Exception ex) { logger.error("LDAP reconciliation failed for {}", row.getString("user_role"), ex); }
                }
            }
            catch (Exception ex) { logger.error("LDAP reconciliation failed", ex); }
        }, 10, 60, TimeUnit.SECONDS);
        started = true;
    }

    private String policy(LdapConfiguration config)
    {
        try
        {
            List<String> entries = new ArrayList<>();
            entries.add(config.getLdapUri());
            entries.add(config.getLdapFilterTemplate());
            entries.add(config.getLdapServiceDn());
            for (GroupRoleMapping mapping : config.getGroupRoleMappings())
            {
                for (String role : mapping.getCassandraRoles()) entries.add(mapping.getNormalizedLdapGroupDn() + "\u0000role\u0000" + role);
                for (KeyspacePermissionGrant grant : mapping.getKeyspacePermissionGrants()) entries.add(mapping.getNormalizedLdapGroupDn() + "\u0000permission\u0000" + encode(grant));
            }
            Collections.sort(entries);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String entry : entries)
            {
                byte[] bytes = entry.getBytes(StandardCharsets.UTF_8);
                digest.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array());
                digest.update(bytes);
            }
            String hash = Base64.getEncoder().encodeToString(digest.digest());
            UntypedResultSet policyRow = QueryProcessor.execute("SELECT policy FROM ldap_auth.coordinator WHERE id='global'", ConsistencyLevel.QUORUM);
            if (policyRow.isEmpty())
                QueryProcessor.execute("INSERT INTO ldap_auth.coordinator (id, policy) VALUES ('global', ?) IF NOT EXISTS", ConsistencyLevel.QUORUM, hash);
            String active = QueryProcessor.execute("SELECT policy FROM ldap_auth.coordinator WHERE id='global'", ConsistencyLevel.QUORUM).one().getString("policy");
            if (!hash.equals(active)) throw new IllegalStateException("LDAP policy mismatch. Local policy fingerprint: " + hash);
            return hash;
        }
        catch (RuntimeException ex) { throw ex; }
        catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    boolean sync(String userRoleName, LdapConfiguration config)
    {
        String hash = policy(config);
        UUID owner = UUID.randomUUID();
        acquire(owner, hash);
        try
        {
            Set<String> groups = DefaultLDAPServer.lookupGroups(userRoleName, config);
            Set<String> desiredRoles = config.resolveGrantedRoles(groups);
            Set<KeyspacePermissionGrant> desiredPermissions = config.resolveGrantedKeyspacePermissions(groups);
            for (String role : desiredRoles)
                if (roles.roleMissing(role)) throw new IllegalStateException("Mapped role does not exist: " + role);
            for (KeyspacePermissionGrant permission : desiredPermissions)
            {
                org.apache.cassandra.auth.DataResource resource = org.apache.cassandra.auth.DataResource.keyspace(permission.getKeyspace());
                if (!resource.exists() || !resource.applicablePermissions().contains(org.apache.cassandra.auth.Permission.valueOf(permission.getGrant())))
                    throw new IllegalStateException("Invalid keyspace permission: " + permission);
            }
            UntypedResultSet state = QueryProcessor.execute("SELECT roles, permissions FROM ldap_auth.assignments WHERE user_role=?", ConsistencyLevel.QUORUM, userRoleName);
            Set<String> ownedRoles = new HashSet<>();
            Set<KeyspacePermissionGrant> ownedPermissions = new HashSet<>();
            if (!state.isEmpty())
            {
                UntypedResultSet.Row row = state.one();
                if (row.has("roles")) ownedRoles.addAll(row.getSet("roles", UTF8Type.instance));
                if (row.has("permissions")) for (String permission : row.getSet("permissions", UTF8Type.instance)) ownedPermissions.add(decode(permission));
            }
            Set<String> additions = new HashSet<>(desiredRoles);
            additions.removeAll(roles.getRole(userRoleName, ConsistencyLevel.QUORUM).getMemberOf());
            ownedRoles.addAll(additions);
            Set<KeyspacePermissionGrant> permissionAdditions = new HashSet<>(desiredPermissions);
            permissionAdditions.removeAll(roles.getGrantedKeyspacePermissions(userRoleName));
            ownedPermissions.addAll(permissionAdditions);
            // Record ownership before any grant so an interrupted operation can be reconciled.
            save(userRoleName, ownedRoles, ownedPermissions);
            Set<String> retainedRoles = new HashSet<>(desiredRoles);
            retainedRoles.retainAll(roles.getRole(userRoleName, ConsistencyLevel.QUORUM).getMemberOf());
            Set<KeyspacePermissionGrant> retainedPermissions = new HashSet<>(desiredPermissions);
            retainedPermissions.retainAll(roles.getGrantedKeyspacePermissions(userRoleName));
            roles.syncGrantedRoles(userRoleName, retainedRoles, ownedRoles);
            roles.syncGrantedKeyspacePermissions(userRoleName, retainedPermissions, ownedPermissions);
            roles.syncGrantedRoles(userRoleName, desiredRoles, ownedRoles);
            roles.syncGrantedKeyspacePermissions(userRoleName, desiredPermissions, ownedPermissions);
            ownedRoles.retainAll(desiredRoles);
            ownedPermissions.retainAll(desiredPermissions);
            save(userRoleName, ownedRoles, ownedPermissions);
            return !groups.isEmpty();
        }
        catch (Exception ex) { throw new IllegalStateException("LDAP access synchronization failed for " + userRoleName, ex); }
        finally
        {
            if (!QueryProcessor.execute("UPDATE ldap_auth.coordinator SET owner=null WHERE id='global' IF owner=?", ConsistencyLevel.QUORUM, owner).one().getBoolean("[applied]"))
                throw new IllegalStateException("LDAP synchronization ownership lost");
        }
    }

    private void acquire(UUID owner, String hash)
    {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (System.nanoTime() < deadline)
        {
            UntypedResultSet.Row row = QueryProcessor.execute("SELECT owner, policy FROM ldap_auth.coordinator WHERE id='global'", ConsistencyLevel.QUORUM).one();
            if (!hash.equals(row.getString("policy"))) throw new IllegalStateException("LDAP policy changed");
            if (!row.has("owner"))
            {
                try
                {
                    if (QueryProcessor.execute("UPDATE ldap_auth.coordinator SET owner=? WHERE id='global' IF owner=null AND policy=?",
                            ConsistencyLevel.QUORUM, owner, hash).one().getBoolean("[applied]")) return;
                }
                catch (org.apache.cassandra.exceptions.CasWriteTimeoutException | org.apache.cassandra.exceptions.CasWriteUnknownResultException ex)
                {
                    // Resolve an uncertain CAS before issuing any permission writes.
                    UntypedResultSet.Row resolved = QueryProcessor.execute("SELECT owner FROM ldap_auth.coordinator WHERE id='global'", ConsistencyLevel.SERIAL).one();
                    if (resolved.has("owner") && owner.equals(resolved.getUUID("owner"))) return;
                }
            }
            try { Thread.sleep(ThreadLocalRandom.current().nextLong(25, 76)); }
            catch (InterruptedException ex)
            {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("LDAP synchronization interrupted", ex);
            }
        }
        throw new IllegalStateException("LDAP synchronization lock wait timed out");
    }

    private void save(String user, Set<String> ownedRoles, Set<KeyspacePermissionGrant> permissions)
    {
        Set<String> encoded = new HashSet<>();
        for (KeyspacePermissionGrant permission : permissions) encoded.add(encode(permission));
        QueryProcessor.execute("INSERT INTO ldap_auth.assignments (user_role, roles, permissions) VALUES (?, ?, ?)", ConsistencyLevel.QUORUM, user, ownedRoles, encoded);
    }

    static String encode(KeyspacePermissionGrant grant) { return grant.getGrant() + ":" + Base64.getEncoder().encodeToString(grant.getKeyspace().getBytes(StandardCharsets.UTF_8)); }
    static KeyspacePermissionGrant decode(String value)
    {
        int separator = value.indexOf(':');
        return new KeyspacePermissionGrant(value.substring(0, separator), new String(Base64.getDecoder().decode(value.substring(separator + 1)), StandardCharsets.UTF_8));
    }
}
