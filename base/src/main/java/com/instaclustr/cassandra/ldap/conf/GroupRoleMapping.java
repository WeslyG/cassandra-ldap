package com.instaclustr.cassandra.ldap.conf;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class GroupRoleMapping
{
    private final String ldapGroupDn;
    private final String normalizedLdapGroupDn;
    private final Set<String> cassandraRoles;

    public GroupRoleMapping(final String ldapGroupDn, final Set<String> cassandraRoles)
    {
        this.ldapGroupDn = ldapGroupDn;
        this.normalizedLdapGroupDn = LdapConfiguration.normalizeDn(ldapGroupDn);
        this.cassandraRoles = Collections.unmodifiableSet(new LinkedHashSet<>(cassandraRoles));
    }

    public String getLdapGroupDn()
    {
        return ldapGroupDn;
    }

    public String getNormalizedLdapGroupDn()
    {
        return normalizedLdapGroupDn;
    }

    public Set<String> getCassandraRoles()
    {
        return cassandraRoles;
    }
}
