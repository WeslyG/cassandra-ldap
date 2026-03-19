package com.instaclustr.cassandra.ldap.auth;

import java.util.Set;

import org.apache.cassandra.auth.LDAPCassandraRoleManager.Role;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.service.ClientState;

public interface SystemAuthRoles {

    boolean roleMissing(String dn);

    void createRole(String userRoleName, boolean superUser);

    void syncGrantedRoles(String userRoleName, Set<String> desiredGrantedRoles, Set<String> managedGrantedRoles);

    boolean hasAdminRole(String role);

    boolean hasAdminRole();

    Role getRole(String name, ConsistencyLevel roleConsistencyLevel);

    void setClientState(ClientState clientState);
}
