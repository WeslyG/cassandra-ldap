package com.instaclustr.cassandra.ldap.auth;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.conf.LdapConfiguration;
import com.instaclustr.cassandra.ldap.hash.Hasher;
import com.instaclustr.cassandra.ldap.utils.ServiceUtils;

public class DefaultLDAPUserRetriever implements UserRetriever {

    private final Hasher hasher;
    private final LdapConfiguration configuration;
    private final boolean dontLoadService;

    public DefaultLDAPUserRetriever(final Hasher hasher, final LdapConfiguration configuration) {
        this.hasher = hasher;
        this.configuration = configuration;
        this.dontLoadService = !configuration.isLoadLdapService();
    }

    @Override
    public User retrieve(final User user) {
        if (dontLoadService)
        {
            return new DefaultLDAPServer().setup(hasher, configuration).retrieve(user);
        }
        else
        {
            return ServiceUtils.getService(LDAPUserRetriever.class, DefaultLDAPServer.class).setup(hasher, configuration).retrieve(user);
        }
    }
}
