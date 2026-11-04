package org.apache.cassandra.auth;

import java.util.Collections;
import com.instaclustr.cassandra.ldap.auth.AbstractSystemAuthRoles;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.service.QueryState;

/** Cassandra 2.2 statement-execution adapter for the shared LDAP access policy. */
public class Cassandra22SystemAuthRoles extends AbstractSystemAuthRoles
{
    @Override
    protected void executeAuthorization(String cql)
    {
        CQLStatement statement = QueryProcessor.getStatement(cql, getClientState()).statement;
        statement.validate(getClientState());
        statement.execute(new QueryState(getClientState()),
            QueryOptions.forInternalCalls(ConsistencyLevel.QUORUM, Collections.emptyList()));
    }
}
