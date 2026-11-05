package com.instaclustr.cassandra.ldap.auth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.instaclustr.cassandra.ldap.conf.LdapSecretResolver;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class LdapSecretResolverTest
{
    private String resolve(String suffix, Object value, Map<String, String> environment) throws Exception
    {
        return LdapSecretResolver.resolve(Collections.singletonMap("ldap_service_password" + suffix, value), environment);
    }

    private void rejected(Map<String, Object> config, Map<String, String> environment) throws Exception
    {
        try
        {
            LdapSecretResolver.resolve(config, environment);
            fail("Expected invalid secret configuration to fail");
        }
        catch (ConfigurationException ex)
        {
            assertFalse(ex.toString().contains("sensitive-value"));
            assertNull(ex.getCause());
        }
    }

    @Test
    public void preservesInlineAndEnvironmentWhitespace() throws Exception
    {
        assertEquals(resolve("", "  sensitive-value  ", Collections.emptyMap()), "  sensitive-value  ");
        assertEquals(resolve("_env", "BIND_PASSWORD", Collections.singletonMap("BIND_PASSWORD", " a\n")), " a\n");
    }

    @Test
    public void rejectsMissingConflictingAndInvalidSources() throws Exception
    {
        rejected(Collections.emptyMap(), Collections.emptyMap());
        String[] suffixes = {"", "_env", "_file", "_credential"};
        for (String first : suffixes)
        {
            rejected(Collections.singletonMap("ldap_service_password" + first, null), Collections.emptyMap());
            rejected(Collections.singletonMap("ldap_service_password" + first, 123), Collections.emptyMap());
            for (String second : suffixes)
            {
                if (first.equals(second)) continue;
                Map<String, Object> config = new HashMap<>();
                config.put("ldap_service_password" + first, "sensitive-value");
                config.put("ldap_service_password" + second, null);
                rejected(config, Collections.emptyMap());
            }
        }
    }

    @Test
    public void rejectsEmptyNulOversizedAndMissingEnvironment() throws Exception
    {
        for (String value : new String[]{"", "sensitive-value\0", String.join("", Collections.nCopies(65537, "x"))})
            rejected(Collections.singletonMap("ldap_service_password", value), Collections.emptyMap());
        rejected(Collections.singletonMap("ldap_service_password_env", "MISSING"), Collections.emptyMap());
        rejected(Collections.singletonMap("ldap_service_password_env", "sensitive-value!"), Collections.emptyMap());
        rejected(Collections.singletonMap("ldap_service_password_env", "EMPTY"), Collections.singletonMap("EMPTY", ""));
        rejected(Collections.singletonMap("ldap_service_password_env", "LARGE"),
                 Collections.singletonMap("LARGE", String.join("", Collections.nCopies(32769, "\u00e4"))));
    }

    @Test
    public void readsUtf8FilesAndRemovesOnlyOneTerminalNewline() throws Exception
    {
        Path file = Files.createTempFile("ldap-secret-", ".txt");
        try
        {
            for (String suffix : new String[]{"", "\n", "\r\n"})
            {
                Files.write(file, ("  p\u00e4ss  " + suffix).getBytes(StandardCharsets.UTF_8));
                assertEquals(resolve("_file", file.toString(), Collections.emptyMap()), "  p\u00e4ss  ");
            }
            Files.write(file, " a\n\n".getBytes(StandardCharsets.UTF_8));
            assertEquals(resolve("_file", file.toString(), Collections.emptyMap()), " a\n");
            for (String ending : new String[]{"\r", "\n", "\r\n"})
            {
                String password = "secret" + ending;
                Files.write(file, (password + "\r\n").getBytes(StandardCharsets.UTF_8));
                assertEquals(resolve("_file", file.toString(), Collections.emptyMap()), password);
            }
            String boundary = String.join("", Collections.nCopies(65536, "x"));
            Files.write(file, boundary.getBytes(StandardCharsets.UTF_8));
            assertEquals(resolve("_file", file.toString(), Collections.emptyMap()), boundary);
        }
        finally { Files.delete(file); }
    }

    @Test
    public void rejectsBadFileContentsAndPaths() throws Exception
    {
        Path file = Files.createTempFile("ldap-secret-", ".txt");
        try
        {
            for (byte[] bytes : new byte[][]{new byte[0], new byte[]{(byte) 0xc3, 0x28}, new byte[65537], new byte[]{0}})
            {
                Files.write(file, bytes);
                rejected(Collections.singletonMap("ldap_service_password_file", file.toString()), Collections.emptyMap());
            }
            rejected(Collections.singletonMap("ldap_service_password_file", file.getParent().toString()), Collections.emptyMap());
        }
        finally { Files.delete(file); }
        rejected(Collections.singletonMap("ldap_service_password_file", file.toString()), Collections.emptyMap());
        rejected(Collections.singletonMap("ldap_service_password_file", "sensitive-value"), Collections.emptyMap());
    }

    @Test
    public void resolvesCredentialAndRejectsTraversalOrMissingDirectory() throws Exception
    {
        Path directory = Files.createTempDirectory("ldap-credentials-");
        Path secret = directory.resolve("ldap-bind-password");
        try
        {
            Files.write(secret, "sensitive-value\n".getBytes(StandardCharsets.UTF_8));
            Map<String, String> env = Collections.singletonMap("CREDENTIALS_DIRECTORY", directory.toString());
            assertEquals(resolve("_credential", "ldap-bind-password", env), "sensitive-value");
            for (String name : new String[]{"../sensitive-value", "/sensitive-value", ".", "..", "missing", "a/b"})
                rejected(Collections.singletonMap("ldap_service_password_credential", name), env);
            rejected(Collections.singletonMap("ldap_service_password_credential", "ldap-bind-password"), Collections.emptyMap());
            rejected(Collections.singletonMap("ldap_service_password_credential", "ldap-bind-password"),
                     Collections.singletonMap("CREDENTIALS_DIRECTORY", "relative"));
        }
        finally { Files.delete(secret); Files.delete(directory); }
    }

    @Test
    public void rejectsCredentialSymlinkEscapeButAllowsSecretVolumeSymlink() throws Exception
    {
        Path directory = Files.createTempDirectory("ldap-credentials-");
        Path outside = Files.createTempFile("ldap-secret-", ".txt");
        Path link = directory.resolve("bind");
        try
        {
            Files.write(outside, "sensitive-value".getBytes(StandardCharsets.UTF_8));
            Files.createSymbolicLink(link, outside);
            rejected(Collections.singletonMap("ldap_service_password_credential", "bind"),
                     Collections.singletonMap("CREDENTIALS_DIRECTORY", directory.toString()));
            assertEquals(resolve("_file", link.toString(), Collections.emptyMap()), "sensitive-value");
        }
        finally { Files.deleteIfExists(link); Files.delete(outside); Files.delete(directory); }
    }

    @Test
    public void yamlLoaderPreservesPasswordAndSuppressesParserExcerpts() throws Exception
    {
        Path file = Files.createTempFile("ldap-config-", ".yaml");
        String property = LdapAuthenticatorConfiguration.LDAP_CONFIG_FILE_PROP;
        String previous = System.getProperty(property);
        try
        {
            System.setProperty(property, file.toString());
            String yaml = "ldap_uri: ldap://ldap.example.org/dc=example,dc=org\n"
                + "ldap_service_dn: cn=service,dc=example,dc=org\n"
                + "ldap_service_password: '  sensitive-value  '\n"
                + "group_role_mappings:\n  - ldap_group_dn: cn=users,dc=example,dc=org\n"
                + "    cassandra_roles: [reader]\n";
            Files.write(file, yaml.getBytes(StandardCharsets.UTF_8));
            assertEquals(new LdapAuthenticatorConfiguration().parseConfiguration().getLdapServicePassword(), "  sensitive-value  ");
            Files.write(file, "ldap_service_password: [sensitive-value\n".getBytes(StandardCharsets.UTF_8));
            try
            {
                new LdapAuthenticatorConfiguration().parseConfiguration();
                fail("Expected invalid YAML to fail");
            }
            catch (ConfigurationException ex)
            {
                assertFalse(ex.toString().contains("sensitive-value"));
                assertNull(ex.getCause());
            }
        }
        finally
        {
            if (previous == null) System.clearProperty(property);
            else System.setProperty(property, previous);
            Files.delete(file);
        }
    }
}
