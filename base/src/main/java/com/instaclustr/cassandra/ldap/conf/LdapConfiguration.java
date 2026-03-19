package com.instaclustr.cassandra.ldap.conf;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.ALLOW_EMPTY_PASSWORD_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_AUTH_CACHE_ENABLED_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_LDAP_ADMIN_USER;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CONSISTENCY_FOR_ROLE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CONTEXT_FACTORY_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.DEFAULT_CONTEXT_FACTORY;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.DEFAULT_CONSISTENCY_FOR_ROLE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.FILTER_TEMPLATE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.GENSALT_LOG2_ROUNDS_DEFAULT;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.GENSALT_LOG2_ROUNDS_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_URI_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LOAD_LDAP_SERVICE_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.PASSWORD_KEY;

import javax.naming.Context;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

public final class LdapConfiguration
{
    private final String ldapUri;
    private final String ldapServiceDn;
    private final String ldapServicePassword;
    private final String ldapFilterTemplate;
    private final String ldapContextFactory;
    private final boolean authCacheEnabled;
    private final boolean allowEmptyPassword;
    private final int authBcryptGensaltLog2Rounds;
    private final boolean loadLdapService;
    private final String cassandraLdapAdminUser;
    private final String consistencyForRole;
    private final List<GroupRoleMapping> groupRoleMappings;

    public LdapConfiguration(final String ldapUri,
                             final String ldapServiceDn,
                             final String ldapServicePassword,
                             final String ldapFilterTemplate,
                             final String ldapContextFactory,
                             final boolean authCacheEnabled,
                             final boolean allowEmptyPassword,
                             final int authBcryptGensaltLog2Rounds,
                             final boolean loadLdapService,
                             final String cassandraLdapAdminUser,
                             final String consistencyForRole,
                             final List<GroupRoleMapping> groupRoleMappings)
    {
        this.ldapUri = ldapUri;
        this.ldapServiceDn = ldapServiceDn;
        this.ldapServicePassword = ldapServicePassword;
        this.ldapFilterTemplate = ldapFilterTemplate;
        this.ldapContextFactory = ldapContextFactory;
        this.authCacheEnabled = authCacheEnabled;
        this.allowEmptyPassword = allowEmptyPassword;
        this.authBcryptGensaltLog2Rounds = authBcryptGensaltLog2Rounds;
        this.loadLdapService = loadLdapService;
        this.cassandraLdapAdminUser = cassandraLdapAdminUser;
        this.consistencyForRole = consistencyForRole;
        this.groupRoleMappings = Collections.unmodifiableList(groupRoleMappings);
    }

    public String getLdapUri()
    {
        return ldapUri;
    }

    public String getLdapServiceDn()
    {
        return ldapServiceDn;
    }

    public String getLdapServicePassword()
    {
        return ldapServicePassword;
    }

    public String getLdapFilterTemplate()
    {
        return ldapFilterTemplate;
    }

    public String getLdapContextFactory()
    {
        return ldapContextFactory;
    }

    public boolean isAuthCacheEnabled()
    {
        return authCacheEnabled;
    }

    public boolean isAllowEmptyPassword()
    {
        return allowEmptyPassword;
    }

    public int getAuthBcryptGensaltLog2Rounds()
    {
        return authBcryptGensaltLog2Rounds;
    }

    public boolean isLoadLdapService()
    {
        return loadLdapService;
    }

    public String getCassandraLdapAdminUser()
    {
        return cassandraLdapAdminUser;
    }

    public String getConsistencyForRole()
    {
        return consistencyForRole;
    }

    public List<GroupRoleMapping> getGroupRoleMappings()
    {
        return groupRoleMappings;
    }

    public Set<String> getMappedLdapGroupDns()
    {
        final Set<String> mappedLdapGroupDns = new LinkedHashSet<>();

        for (final GroupRoleMapping groupRoleMapping : groupRoleMappings)
        {
            mappedLdapGroupDns.add(groupRoleMapping.getLdapGroupDn());
        }

        return mappedLdapGroupDns;
    }

    public Set<String> getManagedCassandraRoles()
    {
        final Set<String> managedCassandraRoles = new LinkedHashSet<>();

        for (final GroupRoleMapping groupRoleMapping : groupRoleMappings)
        {
            managedCassandraRoles.addAll(groupRoleMapping.getCassandraRoles());
        }

        return managedCassandraRoles;
    }

    public Set<String> resolveGrantedRoles(final Set<String> ldapGroupDns)
    {
        final Set<String> normalizedUserGroups = new LinkedHashSet<>();
        for (final String ldapGroupDn : ldapGroupDns)
        {
            normalizedUserGroups.add(normalizeDn(ldapGroupDn));
        }

        final Set<String> grantedRoles = new LinkedHashSet<>();
        for (final GroupRoleMapping groupRoleMapping : groupRoleMappings)
        {
            if (normalizedUserGroups.contains(groupRoleMapping.getNormalizedLdapGroupDn()))
            {
                grantedRoles.addAll(groupRoleMapping.getCassandraRoles());
            }
        }

        return grantedRoles;
    }

    public Properties toProperties()
    {
        final Properties properties = new Properties();

        properties.put(Context.SECURITY_AUTHENTICATION, "simple");
        properties.put("com.sun.jndi.ldap.read.timeout", "1000");
        properties.put("com.sun.jndi.ldap.connect.timeout", "2000");
        properties.put("com.sun.jndi.ldap.connect.pool", "true");

        properties.setProperty(LDAP_URI_PROP, ldapUri);
        properties.setProperty(LDAP_DN, ldapServiceDn);
        properties.setProperty(PASSWORD_KEY, ldapServicePassword);
        properties.setProperty(FILTER_TEMPLATE, ldapFilterTemplate);
        properties.setProperty(CONTEXT_FACTORY_PROP, ldapContextFactory == null ? DEFAULT_CONTEXT_FACTORY : ldapContextFactory);
        properties.setProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP, Boolean.toString(authCacheEnabled));
        properties.setProperty(ALLOW_EMPTY_PASSWORD_PROP, Boolean.toString(allowEmptyPassword));
        properties.setProperty(GENSALT_LOG2_ROUNDS_PROP, Integer.toString(authBcryptGensaltLog2Rounds <= 0 ? GENSALT_LOG2_ROUNDS_DEFAULT : authBcryptGensaltLog2Rounds));
        properties.setProperty(LOAD_LDAP_SERVICE_PROP, Boolean.toString(loadLdapService));
        properties.setProperty(CASSANDRA_LDAP_ADMIN_USER, cassandraLdapAdminUser == null ? "cassandra" : cassandraLdapAdminUser);
        properties.setProperty(CONSISTENCY_FOR_ROLE, consistencyForRole == null ? DEFAULT_CONSISTENCY_FOR_ROLE : consistencyForRole);

        return properties;
    }

    public static String normalizeDn(final String dn)
    {
        if (dn == null)
        {
            return null;
        }

        return dn.trim().toLowerCase(Locale.ROOT);
    }
}
