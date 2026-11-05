# LDAP Bind Secrets

All six Cassandra adapters use the same Java 8-compatible resolver. Choose exactly
one top-level key in `ldap.yaml`; remove every other password key, even if null.
No automatic environment substitution, source precedence or fallback occurs.

| Key | Value |
|---|---|
| `ldap_service_password` | Literal password, preferably only for development |
| `ldap_service_password_env` | Environment variable name, e.g. `CASSANDRA_LDAP_SERVICE_PASSWORD` |
| `ldap_service_password_file` | Absolute UTF-8 file path, e.g. `/run/secrets/ldap-bind-password` |
| `ldap_service_password_credential` | systemd credential name, e.g. `ldap-bind-password` |

The configured value must be a nonempty YAML string. Passwords are not trimmed:
leading/trailing spaces are significant. File and credential sources remove
exactly one terminal LF or CRLF; inline/ENV sources preserve terminal newlines.
Generate files without an editor-added newline. To preserve an intentional
terminal CR or LF in the password, append one additional CRLF terminator to the
file, or use inline/ENV (which performs no newline removal).
Values must be nonempty, contain no NUL and fit in 65536 UTF-8 bytes
(file limit includes the optional terminal newline). Invalid UTF-8 files fail.
Use quoted strings for inline YAML values that resemble numbers/booleans.

Missing variables, unreadable/missing/nonregular files, invalid source names,
empty secrets and conflicting keys prevent Cassandra startup. File symlinks are
supported for secret-volume rotation. Credential names are simple filename
components, at most 255 ASCII characters, beginning with an alphanumeric followed
by alphanumerics, dots, underscores or hyphens. Credential symlinks must resolve
inside the real credential directory; traversal outside it is rejected.

## Encrypted systemd Credentials

Use systemd with `systemd-creds encrypt` and `LoadCredentialEncrypted=` support
(systemd 250 or newer; check distribution backports). Inspect the **actual**
Cassandra unit and service identity before deploying:

```sh
systemd --version
systemd-creds --help
systemctl cat cassandra.service
systemctl show cassandra.service -p User -p Group -p ExecStart
```

Configure this password source in `ldap.yaml`:

```yaml
ldap_service_password_credential: ldap-bind-password
```

Create the encrypted credential on the target Cassandra node as root. Prompting
avoids placing the plaintext in shell history or command arguments:

```sh
install -d -m 0700 /etc/credstore.encrypted
umask 077
systemd-ask-password 'LDAP bind password:' | systemd-creds encrypt --name=ldap-bind-password - /etc/credstore.encrypted/cassandra-ldap-password.cred
```

Default encryption selects a host key and/or TPM according to availability.
For host-key-only operation explicitly use `--with-key=host`; do not use
`--with-key=null`. Protect `/var/lib/systemd/credential.secret`, its backups and
the ciphertext. A host key and ciphertext stored together are not protection
against root or a complete disk theft. TPM-bound encryption has separate hardware
and recovery requirements. Do not assume ciphertext works on another node.

Create `/etc/systemd/system/cassandra.service.d/ldap-credential.conf`:

```ini
[Service]
LoadCredentialEncrypted=ldap-bind-password:/etc/credstore.encrypted/cassandra-ldap-password.cred
```

```sh
systemctl daemon-reload
systemctl restart cassandra.service
systemctl is-active cassandra.service
```

Roll nodes one at a time and verify native administration and LDAP login on each.
systemd decrypts at activation and supplies `CREDENTIALS_DIRECTORY`; the plugin
reads the named file directly. It does not run `systemd-creds` or hardcode a
runtime path. Do not set `CREDENTIALS_DIRECTORY` yourself in production.
Run the actual Cassandra process under the unit's `User=cassandra` (adapt the
account to your package). If a root-owned wrapper later drops privileges, ensure
the resulting JVM can access its credential; a successful root-only probe does
not establish this. Wrappers must preserve `CREDENTIALS_DIRECTORY`.

Credentials are read-only and fixed for a service activation. Consider
`PrivateMounts=yes` for isolation, but test any sandbox changes against your
package's Cassandra startup, storage and management tooling. See the primary
[systemd credential documentation](https://systemd.io/CREDENTIALS/).

## ENV and External Secret Files

For ENV, use this YAML instead of any other password key:

```yaml
ldap_service_password_env: CASSANDRA_LDAP_SERVICE_PASSWORD
```

An alternative systemd drop-in is:

```ini
[Service]
EnvironmentFile=/etc/cassandra/ldap-secret.env
```

Provision that file as root-owned mode 0600 with a quoted systemd environment-file
assignment named `CASSANDRA_LDAP_SERVICE_PASSWORD`. Use systemd EnvironmentFile
quoting, not arbitrary shell script syntax; the file is not executed by a shell.
It remains a plaintext file, and the password enters the process environment
and descendants. ENV is a fallback, not a security equivalent to credentials.
Use a UTF-8 JVM/service locale for non-ASCII environment values, particularly
on Java 8; file and credential contents are explicitly decoded as UTF-8.
Never pass the password through JVM `-D` options or command arguments.

For Docker/Kubernetes-style mounted secrets, configure instead:

```yaml
ldap_service_password_file: /run/secrets/ldap-bind-password
```

Mount it read-only and restrict access to the JVM user. Relative paths are not
accepted. The plugin does not expand environment variables inside paths.

## Rotation and Ansible

The authenticator and role manager each resolve their configuration during
startup. Keep the source stable throughout startup; there is no live reload.
Use atomic file replacement, a systemd daemon reload if the drop-in changed,
and a rolling service restart to adopt a new password. Replacing encrypted
credentials does not alter a running service's copy. Password contents and
source selectors are excluded from the access-policy fingerprint: rotating a
secret does not require a journal policy migration.

Changing a source does not change the password in LDAP. Coordinate the directory
cutover with node restarts. If the directory cannot accept old and new credentials
at the same time, nodes still using the old password will reject LDAP operations
until restarted; a rolling restart alone cannot guarantee uninterrupted LDAP
login. Keep native administrative access available throughout the rotation.

For Ansible, template public YAML and the unit drop-in normally. Retrieve secrets
with Vault/a secret lookup and use separate `no_log: true`, `diff: false` tasks.
Encrypt on **each target node**, supplying plaintext through stdin rather than
argv or a generated public template. If using a temporary plaintext file, create
it mode 0600 on protected ephemeral storage and remove it in an `always` block.
Version the secret deployment separately: encrypting again produces different
ciphertext, so do not use ciphertext equality for idempotence. Stage/verify the
new encrypted file before atomic replacement, record a nonsecret rotation
version, and notify the rolling restart only on an intentional version change.

No secret values or source-specific exception causes are logged by the resolver;
YAML parser errors suppress source excerpts too. The password necessarily exists
as a Java String and in JNDI credentials, including the Properties contract
for LDAP service providers. This is not zeroization or protection against root,
debuggers, JVM compromise or heap dumps. Restrict diagnostic dumps and never log
the configuration/Properties object in custom providers.

## Verification

See [the integration guide](molecule/integration/README.md) for `make
integration-systemd`. This runs both Cassandra nodes under real PID-1 systemd,
with actual host-key encryption, service credential loading and LDAP login for
every adapter. It also verifies fail-closed startup, corrupted ciphertext and
credential rotation. TPM-bound encryption and distribution-specific production
unit wrappers require separate testing on the target hosts.
