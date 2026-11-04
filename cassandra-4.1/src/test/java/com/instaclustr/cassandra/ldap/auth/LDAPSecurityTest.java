package com.instaclustr.cassandra.ldap.auth;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class LDAPSecurityTest
{
    @Test
    public void escapesFilterMetacharacters()
    {
        assertEquals(DefaultLDAPServer.escapeFilterValue("a*)(uid=*)\\\u0000"),
                     "a\\2a\\29\\28uid=\\2a\\29\\5c\\00");
        assertEquals(DefaultLDAPServer.escapeFilterValue("alice"), "alice");
    }

    @Test(expectedExceptions = LDAPAuthFailedException.class)
    public void rejectsEmptyPasswordBeforeOpeningLdap()
    {
        new DefaultLDAPServer().retrieve(new User("alice", ""));
    }

    @Test(expectedExceptions = LDAPAuthFailedException.class)
    public void rejectsMissingPasswordBeforeOpeningLdap()
    {
        new DefaultLDAPServer().retrieve(new User("alice"));
    }
}
