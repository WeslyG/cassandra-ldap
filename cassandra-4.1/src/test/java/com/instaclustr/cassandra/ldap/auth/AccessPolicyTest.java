package com.instaclustr.cassandra.ldap.auth;

import com.instaclustr.cassandra.ldap.conf.*;
import java.util.*;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

public class AccessPolicyTest
{
    private LdapConfiguration config(GroupRoleMapping... mappings)
    {
        return new LdapConfiguration("ldap://localhost/dc=example", "cn=service", "secret", "(uid=%s)",
            "com.sun.jndi.ldap.LdapCtxFactory", false, false, 10, false, "cassandra", "QUORUM", Arrays.asList(mappings));
    }

    private GroupRoleMapping mapping(String dn, String role, String grant)
    {
        return new GroupRoleMapping(dn, Collections.singleton(role),
            Collections.singleton(new KeyspacePermissionGrant(grant, "ks")));
    }

    @Test public void combinesGroupsAndDeduplicates()
    {
        LdapConfiguration config = config(mapping("cn=a", "reader", "SELECT"), mapping("cn=z", "reader", "MODIFY"));
        assertEquals(config.resolveGrantedRoles(new HashSet<>(Arrays.asList("cn=a", "cn=z"))), Collections.singleton("reader"));
        assertEquals(config.resolveGrantedKeyspacePermissions(new HashSet<>(Arrays.asList("cn=a", "cn=z"))).size(), 2);
    }

    @Test public void removalOfOneGroupKeepsOnlyRemainingPermissions()
    {
        LdapConfiguration config = config(mapping("cn=a", "reader", "SELECT"), mapping("cn=z", "writer", "MODIFY"));
        assertEquals(config.resolveGrantedKeyspacePermissions(Collections.singleton("cn=a")),
            Collections.singleton(new KeyspacePermissionGrant("SELECT", "ks")));
        assertEquals(config.resolveGrantedRoles(Collections.singleton("cn=a")), Collections.singleton("reader"));
    }

    @Test public void noGroupsProducesEmptyTarget()
    {
        LdapConfiguration config = config(mapping("cn=a", "reader", "SELECT"));
        assertTrue(config.resolveGrantedRoles(Collections.emptySet()).isEmpty());
        assertTrue(config.resolveGrantedKeyspacePermissions(Collections.emptySet()).isEmpty());
    }

    @Test public void journalEncodingPreservesExactKeyspace()
    {
        KeyspacePermissionGrant grant = new KeyspacePermissionGrant("SELECT", "CaseSensitive:Keyspace");
        assertEquals(LdapAccessSync.decode(LdapAccessSync.encode(grant)), grant);
    }
}
