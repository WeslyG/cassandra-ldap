-- Create ldap_auth first with NetworkTopologyStrategy and production replication
-- for every DC. Only database administrators may access this keyspace.
CREATE TABLE IF NOT EXISTS ldap_auth.coordinator (
    id text PRIMARY KEY,
    policy text,
    owner uuid
);
CREATE TABLE IF NOT EXISTS ldap_auth.assignments (
    user_role text PRIMARY KEY,
    roles set<text>,
    permissions set<text>
);
