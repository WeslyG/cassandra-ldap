package com.instaclustr.cassandra.ldap.conf;

import org.apache.cassandra.auth.Permission;

public final class KeyspacePermissionGrant
{
    private final String grant;
    private final String keyspace;

    public KeyspacePermissionGrant(final String grant, final String keyspace)
    {
        this.grant = normalizeGrant(grant);
        this.keyspace = normalizeKeyspace(keyspace);
    }

    public String getGrant()
    {
        return grant;
    }

    public String getKeyspace()
    {
        return keyspace;
    }

    @Override
    public boolean equals(final Object other)
    {
        if (this == other)
        {
            return true;
        }

        if (!(other instanceof KeyspacePermissionGrant))
        {
            return false;
        }

        final KeyspacePermissionGrant that = (KeyspacePermissionGrant) other;
        return grant.equals(that.grant) && keyspace.equals(that.keyspace);
    }

    @Override
    public int hashCode()
    {
        return 31 * grant.hashCode() + keyspace.hashCode();
    }

    @Override
    public String toString()
    {
        return grant + " ON KEYSPACE " + keyspace;
    }

    private static String normalizeGrant(final String grant)
    {
        if (grant == null || grant.trim().isEmpty())
        {
            throw new IllegalArgumentException("Permission grant can not be empty.");
        }

        return Permission.valueOf(grant.trim().toUpperCase()).name();
    }

    private static String normalizeKeyspace(final String keyspace)
    {
        if (keyspace == null || keyspace.trim().isEmpty())
        {
            throw new IllegalArgumentException("Permission keyspace can not be empty.");
        }

        return keyspace.trim();
    }
}
