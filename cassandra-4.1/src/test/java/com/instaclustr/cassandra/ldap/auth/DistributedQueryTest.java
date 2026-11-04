package com.instaclustr.cassandra.ldap.auth;

import java.util.Collections;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

public class DistributedQueryTest
{
    @Test public void quotesPrincipalWithoutInterpretingItsQuestionMarks()
    {
        assertEquals(DistributedQuery.bind("SELECT * FROM x WHERE role=? AND policy=?", "cn=a'?", "p"),
            "SELECT * FROM x WHERE role='cn=a''?' AND policy='p'");
    }

    @Test public void quotesSetElements()
    {
        assertEquals(DistributedQuery.bind("UPDATE x SET roles=?", Collections.singleton("role'")),
            "UPDATE x SET roles={'role'''}");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void rejectsMissingParameters() { DistributedQuery.bind("SELECT * FROM x WHERE role=?"); }
}
