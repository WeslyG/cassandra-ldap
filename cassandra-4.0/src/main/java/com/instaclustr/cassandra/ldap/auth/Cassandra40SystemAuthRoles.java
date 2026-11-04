/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.instaclustr.cassandra.ldap.auth;

import java.util.Collections;
import com.instaclustr.cassandra.ldap.auth.AbstractSystemAuthRoles;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.service.QueryState;

/** Cassandra 4.0 statement-execution adapter for the shared LDAP access policy. */
public class Cassandra40SystemAuthRoles extends AbstractSystemAuthRoles
{
    @Override
    protected void executeAuthorization(String cql)
    {
        CQLStatement statement = QueryProcessor.getStatement(cql, getClientState());
        statement.validate(getClientState());
        statement.execute(new QueryState(getClientState()),
            QueryOptions.forInternalCalls(ConsistencyLevel.QUORUM, Collections.emptyList()), System.nanoTime());
    }
}
