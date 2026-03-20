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
package com.instaclustr.cassandra.ldap.conf;

import static java.lang.String.format;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

/**
 * Configuration loaded from ldap.yaml file.
 */
public final class LdapAuthenticatorConfiguration
{

    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticatorConfiguration.class);

    public static final String LDAP_CONFIG_FILE_PROP = "cassandra.ldap.config.file";
    public static final String LDAP_CONFIG_FILENAME = "ldap.yaml";

    public static final String LDAP_URI_PROP = "ldap_uri";
    public static final String CONTEXT_FACTORY_PROP = "ldap_context_factory";
    public static final String LDAP_DN = "ldap_service_dn";
    public static final String PASSWORD_KEY = "ldap_service_password";
    public static final String FILTER_TEMPLATE = "ldap_filter_template";
    public static final String GROUP_ROLE_MAPPINGS = "group_role_mappings";
    public static final String GROUP_ROLE_MAPPING_LDAP_GROUP_DN = "ldap_group_dn";
    public static final String GROUP_ROLE_MAPPING_CASSANDRA_ROLES = "cassandra_roles";
    public static final String GROUP_ROLE_MAPPING_PERMISSION_GRANT = "grant";
    public static final String GROUP_ROLE_MAPPING_PERMISSION_KEYSPACE = "keyspace";

    public static final String CASSANDRA_AUTH_CACHE_ENABLED_PROP = "auth_cache_enabled";
    public static final String ALLOW_EMPTY_PASSWORD_PROP = "allow_empty_password";
    public static final String GENSALT_LOG2_ROUNDS_PROP = "auth_bcrypt_gensalt_log2_rounds";
    public static final String LOAD_LDAP_SERVICE_PROP = "load_ldap_service";
    public static final int GENSALT_LOG2_ROUNDS_DEFAULT = 10;

    public static final String DEFAULT_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final String CASSANDRA_LDAP_ADMIN_USER_SYSTEM_PROPERTY = "cassandra.ldap.admin.user";
    public static final String CASSANDRA_LDAP_ADMIN_USER = "cassandra_ldap_admin_user";
    public static final String CONSISTENCY_FOR_ROLE = "consistency_for_role";
    public static final String DEFAULT_CONSISTENCY_FOR_ROLE = "LOCAL_ONE";

    public LdapConfiguration parseConfiguration() throws ConfigurationException
    {
        final File configurationFile = resolveConfigurationFile();
        final Map<?, ?> root = loadYaml(configurationFile);

        final String ldapUri = requireString(root, LDAP_URI_PROP, configurationFile);
        final String ldapServiceDn = requireString(root, LDAP_DN, configurationFile);
        final String ldapServicePassword = requireString(root, PASSWORD_KEY, configurationFile);
        final String ldapFilterTemplate = optionalString(root, FILTER_TEMPLATE, "(cn=%s)");
        final String ldapContextFactory = optionalString(root, CONTEXT_FACTORY_PROP, DEFAULT_CONTEXT_FACTORY);
        final boolean authCacheEnabled = optionalBoolean(root, CASSANDRA_AUTH_CACHE_ENABLED_PROP, true);
        final boolean allowEmptyPassword = optionalBoolean(root, ALLOW_EMPTY_PASSWORD_PROP, true);
        final int bcryptRounds = optionalInt(root, GENSALT_LOG2_ROUNDS_PROP, GENSALT_LOG2_ROUNDS_DEFAULT);
        final boolean loadLdapService = optionalBoolean(root, LOAD_LDAP_SERVICE_PROP, false);
        final String consistencyForRole = optionalString(root, CONSISTENCY_FOR_ROLE, DEFAULT_CONSISTENCY_FOR_ROLE);

        if (!ldapFilterTemplate.contains("%s"))
        {
            throw new ConfigurationException(String.format("Filter template property %s has to contain placeholder '\\%s'", FILTER_TEMPLATE));
        }

        final String adminUserFromProperty = System.getProperty(CASSANDRA_LDAP_ADMIN_USER_SYSTEM_PROPERTY);
        final String cassandraLdapAdminUser = adminUserFromProperty == null
            ? optionalString(root, CASSANDRA_LDAP_ADMIN_USER, "cassandra")
            : adminUserFromProperty;

        final List<GroupRoleMapping> groupRoleMappings = parseGroupRoleMappings(root.get(GROUP_ROLE_MAPPINGS), configurationFile);

        if (groupRoleMappings.isEmpty())
        {
            throw new ConfigurationException(format("%s must contain at least one mapping in %s",
                                                    GROUP_ROLE_MAPPINGS,
                                                    configurationFile.getAbsolutePath()));
        }

        return new LdapConfiguration(ldapUri,
                                     ldapServiceDn,
                                     ldapServicePassword,
                                     ldapFilterTemplate,
                                     ldapContextFactory,
                                     authCacheEnabled,
                                     allowEmptyPassword,
                                     bcryptRounds,
                                     loadLdapService,
                                     cassandraLdapAdminUser,
                                     consistencyForRole,
                                     groupRoleMappings);
    }

    public Properties parseProperties() throws ConfigurationException
    {
        return parseConfiguration().toProperties();
    }

    public static int getGensaltLog2Rounds(final Properties properties)
    {
        try
        {
            final int rounds = Integer.parseInt(properties.getProperty(GENSALT_LOG2_ROUNDS_PROP, String.valueOf(GENSALT_LOG2_ROUNDS_DEFAULT)));

            if (rounds < 4 || rounds > 31)
            {
                logger.warn(format("Unable to parse %s property, setting it to %s", GENSALT_LOG2_ROUNDS_PROP, GENSALT_LOG2_ROUNDS_DEFAULT));
                return GENSALT_LOG2_ROUNDS_DEFAULT;
            }

            return rounds;
        } catch (final NumberFormatException e)
        {
            logger.warn(format("Unable to parse %s property, setting it to %s", GENSALT_LOG2_ROUNDS_PROP, GENSALT_LOG2_ROUNDS_DEFAULT));
            return GENSALT_LOG2_ROUNDS_DEFAULT;
        }
    }

    private File resolveConfigurationFile() throws ConfigurationException
    {
        final String cassandraConfEnvProperty = System.getenv().get("CASSANDRA_CONF");

        File defaultConfigurationFile = null;
        if (cassandraConfEnvProperty != null)
        {
            defaultConfigurationFile = new File(cassandraConfEnvProperty, LDAP_CONFIG_FILENAME);
        }

        final File configFile = new File(System.getProperty(LDAP_CONFIG_FILE_PROP, LDAP_CONFIG_FILENAME));

        final File finalConfigurationFile;
        if (configFile.exists() && configFile.canRead())
        {
            finalConfigurationFile = configFile;
        } else if (defaultConfigurationFile != null && defaultConfigurationFile.exists() && defaultConfigurationFile.canRead())
        {
            finalConfigurationFile = defaultConfigurationFile;
        } else
        {
            throw new ConfigurationException(format(
                "Unable to locate readable LDAP configuration file from system property %s nor from $CASSANDRA_CONF/%s.",
                LDAP_CONFIG_FILE_PROP,
                LDAP_CONFIG_FILENAME));
        }

        logger.info("LDAP configuration file: {}", finalConfigurationFile.getAbsoluteFile());
        return finalConfigurationFile;
    }

    private Map<?, ?> loadYaml(final File configurationFile) throws ConfigurationException
    {
        try (FileInputStream input = new FileInputStream(configurationFile))
        {
            final Object loaded = new Yaml().load(input);

            if (loaded == null)
            {
                throw new ConfigurationException(format("LDAP configuration file %s is empty.", configurationFile.getAbsolutePath()));
            }

            if (!(loaded instanceof Map))
            {
                throw new ConfigurationException(format("LDAP configuration file %s must contain a YAML object at the root.",
                                                        configurationFile.getAbsolutePath()));
            }

            return (Map<?, ?>) loaded;
        } catch (final IOException ex)
        {
            throw new ConfigurationException(format("Could not open LDAP configuration file %s", configurationFile), ex);
        } catch (final RuntimeException ex)
        {
            throw new ConfigurationException(format("Could not parse LDAP configuration file %s: %s",
                                                    configurationFile.getAbsolutePath(),
                                                    ex.getMessage()),
                                             ex);
        }
    }

    private List<GroupRoleMapping> parseGroupRoleMappings(final Object rawMappings, final File configurationFile) throws ConfigurationException
    {
        if (!(rawMappings instanceof List))
        {
            throw new ConfigurationException(format("%s must be a YAML list in %s",
                                                    GROUP_ROLE_MAPPINGS,
                                                    configurationFile.getAbsolutePath()));
        }

        final List<GroupRoleMapping> groupRoleMappings = new ArrayList<>();
        final Set<String> seenGroupDns = new LinkedHashSet<>();

        for (final Object rawMapping : (List<?>) rawMappings)
        {
            if (!(rawMapping instanceof Map))
            {
                throw new ConfigurationException(format("Each entry in %s must be a YAML object in %s",
                                                        GROUP_ROLE_MAPPINGS,
                                                        configurationFile.getAbsolutePath()));
            }

            final Map<?, ?> mapping = (Map<?, ?>) rawMapping;
            final String ldapGroupDn = requireString(mapping, GROUP_ROLE_MAPPING_LDAP_GROUP_DN, configurationFile);
            final GroupRoleTargets groupRoleTargets = parseCassandraRoles(mapping.get(GROUP_ROLE_MAPPING_CASSANDRA_ROLES),
                                                                          configurationFile,
                                                                          ldapGroupDn);

            final String normalizedGroupDn = LdapConfiguration.normalizeDn(ldapGroupDn);
            if (!seenGroupDns.add(normalizedGroupDn))
            {
                throw new ConfigurationException(format("Duplicate LDAP group mapping found for %s in %s",
                                                        ldapGroupDn,
                                                        configurationFile.getAbsolutePath()));
            }

            groupRoleMappings.add(new GroupRoleMapping(ldapGroupDn,
                                                      groupRoleTargets.cassandraRoles,
                                                      groupRoleTargets.keyspacePermissionGrants));
        }

        return groupRoleMappings;
    }

    private GroupRoleTargets parseCassandraRoles(final Object rawRoles, final File configurationFile, final String ldapGroupDn) throws ConfigurationException
    {
        final Set<String> cassandraRoles = new LinkedHashSet<>();
        final Set<KeyspacePermissionGrant> keyspacePermissionGrants = new LinkedHashSet<>();

        if (rawRoles instanceof List)
        {
            for (final Object rawTarget : (List<?>) rawRoles)
            {
                if (rawTarget instanceof String)
                {
                    final String role = normalizeString(rawTarget, GROUP_ROLE_MAPPING_CASSANDRA_ROLES, configurationFile);
                    if (!role.isEmpty())
                    {
                        cassandraRoles.add(role);
                    }
                } else if (rawTarget instanceof Map)
                {
                    keyspacePermissionGrants.addAll(parseKeyspacePermissionGrant((Map<?, ?>) rawTarget, configurationFile, ldapGroupDn));
                } else
                {
                    throw new ConfigurationException(format("%s entries for LDAP group %s must be strings or YAML objects in %s",
                                                            GROUP_ROLE_MAPPING_CASSANDRA_ROLES,
                                                            ldapGroupDn,
                                                            configurationFile.getAbsolutePath()));
                }
            }
        } else if (rawRoles instanceof String)
        {
            for (final String role : ((String) rawRoles).split(","))
            {
                final String trimmedRole = role.trim();
                if (!trimmedRole.isEmpty())
                {
                    cassandraRoles.add(trimmedRole);
                }
            }
        } else
        {
            throw new ConfigurationException(format("%s for LDAP group %s must be a YAML list or comma-separated string in %s",
                                                    GROUP_ROLE_MAPPING_CASSANDRA_ROLES,
                                                    ldapGroupDn,
                                                    configurationFile.getAbsolutePath()));
        }

        if (cassandraRoles.isEmpty() && keyspacePermissionGrants.isEmpty())
        {
            throw new ConfigurationException(format("%s for LDAP group %s can not be empty in %s",
                                                    GROUP_ROLE_MAPPING_CASSANDRA_ROLES,
                                                    ldapGroupDn,
                                                    configurationFile.getAbsolutePath()));
        }

        return new GroupRoleTargets(cassandraRoles, keyspacePermissionGrants);
    }

    private Set<KeyspacePermissionGrant> parseKeyspacePermissionGrant(final Map<?, ?> rawGrant,
                                                                      final File configurationFile,
                                                                      final String ldapGroupDn) throws ConfigurationException
    {
        final String grant = requireString(rawGrant, GROUP_ROLE_MAPPING_PERMISSION_GRANT, configurationFile);
        final String keyspace = requireString(rawGrant, GROUP_ROLE_MAPPING_PERMISSION_KEYSPACE, configurationFile);
        final Set<KeyspacePermissionGrant> permissionGrants = new LinkedHashSet<>();

        try
        {
            if ("ALL".equalsIgnoreCase(grant))
            {
                for (final Permission permission : DataResource.keyspace(keyspace).applicablePermissions())
                {
                    permissionGrants.add(new KeyspacePermissionGrant(permission.name(), keyspace));
                }
                return permissionGrants;
            }

            permissionGrants.add(new KeyspacePermissionGrant(grant, keyspace));
            return permissionGrants;
        } catch (final IllegalArgumentException ex)
        {
            throw new ConfigurationException(format("Invalid keyspace permission grant for LDAP group %s in %s: %s",
                                                    ldapGroupDn,
                                                    configurationFile.getAbsolutePath(),
                                                    ex.getMessage()),
                                             ex);
        }
    }

    private String requireString(final Map<?, ?> root, final String key, final File configurationFile) throws ConfigurationException
    {
        final Object value = root.get(key);
        final String normalizedValue = normalizeString(value, key, configurationFile);

        if (normalizedValue.isEmpty())
        {
            throw new ConfigurationException(format("%s MUST be set in the configuration file %s",
                                                    key,
                                                    configurationFile.getAbsolutePath()));
        }

        return normalizedValue;
    }

    private String optionalString(final Map<?, ?> root, final String key, final String defaultValue)
    {
        final Object value = root.get(key);

        if (value == null)
        {
            return defaultValue;
        }

        final String stringValue = value.toString().trim();
        return stringValue.isEmpty() ? defaultValue : stringValue;
    }

    private boolean optionalBoolean(final Map<?, ?> root, final String key, final boolean defaultValue)
    {
        final Object value = root.get(key);
        if (value == null)
        {
            return defaultValue;
        }

        if (value instanceof Boolean)
        {
            return (Boolean) value;
        }

        return Boolean.parseBoolean(value.toString());
    }

    private int optionalInt(final Map<?, ?> root, final String key, final int defaultValue) throws ConfigurationException
    {
        final Object value = root.get(key);
        if (value == null)
        {
            return defaultValue;
        }

        try
        {
            return Integer.parseInt(value.toString().trim());
        } catch (final NumberFormatException ex)
        {
            throw new ConfigurationException(format("%s must be an integer in LDAP configuration.", key), ex);
        }
    }

    private String normalizeString(final Object value, final String key, final File configurationFile) throws ConfigurationException
    {
        if (value == null)
        {
            return "";
        }

        if (!(value instanceof String))
        {
            throw new ConfigurationException(format("%s must be a string in %s",
                                                    key,
                                                    configurationFile.getAbsolutePath()));
        }

        return value.toString().trim();
    }

    private static final class GroupRoleTargets
    {
        private final Set<String> cassandraRoles;
        private final Set<KeyspacePermissionGrant> keyspacePermissionGrants;

        private GroupRoleTargets(final Set<String> cassandraRoles, final Set<KeyspacePermissionGrant> keyspacePermissionGrants)
        {
            this.cassandraRoles = cassandraRoles;
            this.keyspacePermissionGrants = keyspacePermissionGrants;
        }
    }
}
