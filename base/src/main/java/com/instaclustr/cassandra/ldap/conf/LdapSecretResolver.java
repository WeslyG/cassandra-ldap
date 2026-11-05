package com.instaclustr.cassandra.ldap.conf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;

import org.apache.cassandra.exceptions.ConfigurationException;

/** Resolve one explicit bind-password source without exposing its contents in errors. */
public final class LdapSecretResolver
{
    private static final int MAX_BYTES = 65536;
    private static final String[] KEYS = {
        LdapAuthenticatorConfiguration.PASSWORD_KEY,
        LdapAuthenticatorConfiguration.PASSWORD_ENV_KEY,
        LdapAuthenticatorConfiguration.PASSWORD_FILE_KEY,
        LdapAuthenticatorConfiguration.PASSWORD_CREDENTIAL_KEY
    };

    private LdapSecretResolver() { }

    public static String resolve(Map<?, ?> configuration, Map<String, String> environment) throws ConfigurationException
    {
        String selected = null;
        for (String key : KEYS)
        {
            if (configuration.containsKey(key))
            {
                if (selected != null)
                    throw failure("Exactly one LDAP service password source must be configured");
                selected = key;
            }
        }
        if (selected == null)
            throw failure("Exactly one LDAP service password source must be configured");
        Object value = configuration.get(selected);
        if (!(value instanceof String) || ((String) value).isEmpty())
            throw failure("LDAP service password source must be a nonempty string");
        String source = (String) value;
        String password;
        if (selected.equals(KEYS[0]))
            password = source;
        else if (selected.equals(KEYS[1]))
        {
            if (!source.matches("[A-Za-z_][A-Za-z0-9_]*"))
                throw failure("Invalid LDAP service password environment variable name");
            password = environment.get(source);
        }
        else
        {
            try
            {
                Path path;
                if (selected.equals(KEYS[3]))
                {
                    if (!source.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,254}"))
                        throw failure("Invalid LDAP service password credential name");
                    String directory = environment.get("CREDENTIALS_DIRECTORY");
                    if (directory == null || !Paths.get(directory).isAbsolute())
                        throw failure("LDAP credential requires an absolute CREDENTIALS_DIRECTORY supplied by systemd");
                    Path root = Paths.get(directory).toRealPath();
                    path = root.resolve(source).toRealPath();
                    if (!path.startsWith(root))
                        throw failure("LDAP credential must remain within CREDENTIALS_DIRECTORY");
                }
                else
                {
                    path = Paths.get(source);
                    if (!path.isAbsolute())
                        throw failure("LDAP service password file must use an absolute path");
                }
                password = read(path);
            }
            catch (IOException | RuntimeException ex)
            {
                // Do not retain a cause: filenames or decoder errors can contain sensitive data.
                throw failure("Unable to read LDAP service password file or credential");
            }
        }
        if (password == null || password.isEmpty() || password.indexOf('\0') >= 0
            || password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES)
            throw failure("LDAP service password is missing, empty, contains NUL, or exceeds 65536 UTF-8 bytes");
        return password;
    }

    private static String read(Path path) throws IOException, ConfigurationException
    {
        if (!Files.isRegularFile(path))
            throw failure("LDAP service password source must be a regular file");
        byte[] chunk = new byte[4096];
        byte[] bytes = null;
        try (InputStream input = Files.newInputStream(path);
             ByteArrayOutputStream output = new ByteArrayOutputStream())
        {
            int count;
            while ((count = input.read(chunk)) != -1)
            {
                if (output.size() + count > MAX_BYTES)
                    throw failure("LDAP service password file exceeds 65536 bytes");
                output.write(chunk, 0, count);
            }
            bytes = output.toByteArray();
            String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
            // File sources permit one editor-added newline, never trim password whitespace.
            if (text.endsWith("\n"))
                text = text.substring(0, text.length() - (text.endsWith("\r\n") ? 2 : 1));
            return text;
        }
        catch (CharacterCodingException ex)
        {
            throw failure("LDAP service password file must contain valid UTF-8");
        }
        finally
        {
            Arrays.fill(chunk, (byte) 0);
            if (bytes != null)
                Arrays.fill(bytes, (byte) 0);
        }
    }

    private static ConfigurationException failure(String message)
    {
        return new ConfigurationException(message);
    }
}
