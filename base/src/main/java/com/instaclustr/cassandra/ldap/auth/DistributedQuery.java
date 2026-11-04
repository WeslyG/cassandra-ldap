package com.instaclustr.cassandra.ldap.auth;

import java.util.Set;
import java.util.UUID;
import java.util.StringJoiner;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.db.ConsistencyLevel;

/** Uses the distributed query API common to Cassandra 2.2 through 5.0. */
final class DistributedQuery
{
    static UntypedResultSet execute(String template, ConsistencyLevel consistency, Object... values)
    {
        return QueryProcessor.process(bind(template, values), consistency);
    }

    static String bind(String template, Object... values)
    {
        StringBuilder query = new StringBuilder();
        int offset = 0;
        for (Object value : values)
        {
            int marker = template.indexOf('?', offset);
            if (marker < 0) throw new IllegalArgumentException("Too many query parameters");
            query.append(template, offset, marker).append(literal(value));
            offset = marker + 1;
        }
        if (template.indexOf('?', offset) >= 0) throw new IllegalArgumentException("Missing query parameters");
        return query.append(template.substring(offset)).toString();
    }

    static String literal(Object value)
    {
        if (value instanceof String) return "'" + ((String) value).replace("'", "''") + "'";
        if (value instanceof UUID || value instanceof Boolean) return value.toString();
        if (value instanceof Set)
        {
            StringJoiner values = new StringJoiner(",", "{", "}");
            for (Object entry : (Set<?>) value) values.add(literal(entry));
            return values.toString();
        }
        throw new IllegalArgumentException("Unsupported query parameter type");
    }
}
