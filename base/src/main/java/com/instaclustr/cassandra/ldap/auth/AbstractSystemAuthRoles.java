package com.instaclustr.cassandra.ldap.auth;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import com.instaclustr.cassandra.ldap.conf.KeyspacePermissionGrant;
import com.instaclustr.cassandra.ldap.conf.LdapConfiguration;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.LDAPCassandraRoleManager.Role;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.service.ClientState;

/** Shared policy behavior; subclasses adapt only Cassandra's statement execution ABI. */
public abstract class AbstractSystemAuthRoles implements SystemAuthRoles
{
    private ClientState clientState;
    private final LdapAccessSync sync = new LdapAccessSync(this);
    private final boolean mirrorLegacyWrites;

    protected AbstractSystemAuthRoles()
    {
        boolean legacy;
        try { CassandraAuthorizer.class.getMethod("authWriteConsistencyLevel"); legacy = false; }
        catch (NoSuchMethodException ex) { legacy = true; }
        mirrorLegacyWrites = legacy;
    }

    public void setClientState(ClientState state) { clientState = state; }
    public ClientState getClientState() { return clientState; }
    protected abstract void executeAuthorization(String cql);

    void validateWriteConsistency()
    {
        if (mirrorLegacyWrites) return;
        try
        {
            Method method = CassandraAuthorizer.class.getMethod("authWriteConsistencyLevel");
            Object level = method.invoke(null);
            if (level != ConsistencyLevel.QUORUM && level != ConsistencyLevel.ALL)
                throw new IllegalStateException("LDAP synchronization requires auth_write_consistency_level QUORUM or ALL");
        }
        catch (ReflectiveOperationException ex) { throw new IllegalStateException(ex); }
    }

    public void startSynchronization(LdapConfiguration config) { sync.start(config); }
    public void synchronizeLdapUser(String user, LdapConfiguration config)
    {
        if (!sync.sync(user, config)) throw new AuthenticationException("User is not a member of any configured LDAP group");
    }

    public boolean roleMissing(String role)
    {
        return DistributedQuery.execute("SELECT role FROM system_auth.roles WHERE role=?", ConsistencyLevel.QUORUM, role).isEmpty();
    }

    public boolean hasAdminRole(String role) { return !roleMissing(role); }
    public boolean hasAdminRole() { return hasAdminRole("cassandra"); }

    public Role getRole(String name, ConsistencyLevel consistency)
    {
        UntypedResultSet rows = DistributedQuery.execute("SELECT * FROM system_auth.roles WHERE role=?", consistency, name);
        if (rows.isEmpty()) return new Role(null, false, false, Collections.<String>emptySet());
        UntypedResultSet.Row row = rows.one();
        return new Role(name, row.getBoolean("is_superuser"), row.getBoolean("can_login"),
            row.has("member_of") ? row.getSet("member_of", UTF8Type.instance) : Collections.<String>emptySet());
    }

    public void createRole(String user, boolean superUser)
    {
        executeAuthorization("CREATE ROLE IF NOT EXISTS " + identifier(user) + " WITH LOGIN=true AND SUPERUSER=" + superUser);
        if (mirrorLegacyWrites)
            DistributedQuery.execute("UPDATE system_auth.roles SET is_superuser=?, can_login=true WHERE role=?", ConsistencyLevel.QUORUM, superUser, user);
    }

    public void syncGrantedRoles(String user, Set<String> desired, Set<String> managed)
    {
        Set<String> current = getRole(user, ConsistencyLevel.QUORUM).getMemberOf();
        Set<String> revoke = new HashSet<>(current);
        revoke.retainAll(managed);
        revoke.removeAll(desired);
        for (String role : revoke)
        {
            if (!roleMissing(role)) executeAuthorization("REVOKE " + DistributedQuery.literal(role) + " FROM " + DistributedQuery.literal(user));
            if (mirrorLegacyWrites) mirrorMembership(user, role, false);
        }
        Set<String> grant = new HashSet<>(desired);
        grant.removeAll(current);
        for (String role : grant)
        {
            executeAuthorization("GRANT " + DistributedQuery.literal(role) + " TO " + DistributedQuery.literal(user));
            if (mirrorLegacyWrites) mirrorMembership(user, role, true);
        }
    }

    private void mirrorMembership(String user, String role, boolean grant)
    {
        // Old auth implementations hard-code LOCAL_ONE. Replicate the same validated
        // mutations at QUORUM before releasing the synchronization lock.
        DistributedQuery.execute("UPDATE system_auth.roles SET member_of=member_of" + (grant ? "+" : "-") + "? WHERE role=?",
            ConsistencyLevel.QUORUM, Collections.singleton(role), user);
        if (grant)
            DistributedQuery.execute("INSERT INTO system_auth.role_members (role, member) VALUES (?, ?)", ConsistencyLevel.QUORUM, role, user);
        else
            DistributedQuery.execute("DELETE FROM system_auth.role_members WHERE role=? AND member=?", ConsistencyLevel.QUORUM, role, user);
    }

    public void syncGrantedKeyspacePermissions(String user, Set<KeyspacePermissionGrant> desired, Set<KeyspacePermissionGrant> managed)
    {
        Set<KeyspacePermissionGrant> current = getGrantedKeyspacePermissions(user);
        Set<KeyspacePermissionGrant> revoke = new HashSet<>(current);
        revoke.retainAll(managed);
        revoke.removeAll(desired);
        for (KeyspacePermissionGrant permission : revoke) changePermission(user, permission, false);
        Set<KeyspacePermissionGrant> grant = new HashSet<>(desired);
        grant.removeAll(current);
        for (KeyspacePermissionGrant permission : grant) changePermission(user, permission, true);
    }

    private void changePermission(String user, KeyspacePermissionGrant permission, boolean grant)
    {
        DataResource resource = DataResource.keyspace(permission.getKeyspace());
        if (grant || resource.exists())
            executeAuthorization((grant ? "GRANT " : "REVOKE ") + permission.getGrant() + " ON KEYSPACE "
                + identifier(permission.getKeyspace()) + (grant ? " TO " : " FROM ") + DistributedQuery.literal(user));
        if (mirrorLegacyWrites || !resource.exists())
        {
            DistributedQuery.execute("UPDATE system_auth.role_permissions SET permissions=permissions" + (grant ? "+" : "-")
                + "? WHERE role=? AND resource=?", ConsistencyLevel.QUORUM, Collections.singleton(permission.getGrant()), user, resource.getName());
            if (grant)
                DistributedQuery.execute("INSERT INTO system_auth." + AuthKeyspace.RESOURCE_ROLE_INDEX + " (resource, role) VALUES (?, ?)",
                    ConsistencyLevel.QUORUM, resource.getName(), user);
        }
    }

    Set<KeyspacePermissionGrant> getGrantedKeyspacePermissions(String user)
    {
        Set<KeyspacePermissionGrant> result = new HashSet<>();
        for (UntypedResultSet.Row row : DistributedQuery.execute("SELECT resource, permissions FROM system_auth.role_permissions WHERE role=?", ConsistencyLevel.QUORUM, user))
        {
            String resource = row.getString("resource");
            if (!resource.startsWith("data/")) continue;
            DataResource data = DataResource.fromName(resource);
            if (data.isKeyspaceLevel() && row.has("permissions"))
                for (String permission : row.getSet("permissions", UTF8Type.instance)) result.add(new KeyspacePermissionGrant(permission, data.getKeyspace()));
        }
        return result;
    }

    private static String identifier(String value) { return "\"" + value.replace("\"", "\"\"") + "\""; }
}
