import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from package_release import prepare_release


class ReleasePackagingTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.write(".gitignore", "**/target/\nmolecule/integration/.state/\ndist/\n")
        self.write("pom.xml", '<project xmlns="http://maven.apache.org/POM/4.0.0"><version>1.2.0</version></project>')
        self.write("conf/ldap.yaml", "ldap_service_password: REPLACE_WITH_SECRET\n")
        self.write("SECRET_HANDLING.md", "# Secret sources\n[Tests](molecule/integration/README.md)\n")
        self.write("conf/access-sync-schema.cql", "-- Synthetic schema fixture\n")
        self.write("LICENSE", "Synthetic license fixture\n")
        self.write("CHANGELOG.md", "# Changelog\n\n## 1.2.0 - 2026-11-05\n\n"
                   "- Current fixture change. See [operations](ACCESS_SYNC.md#bind-identity-access-review).\n\n"
                   "## 1.1.0 - 2026-01-01\n\n- Old fixture change.\n")
        self.matrix = {module: {"version": server, "plugin_version": "1.2.0"} for module, server in
                       [("2.2", "2.2.19"), ("3.0", "3.0.31"), ("3.11", "3.11.18"),
                        ("4.0", "4.0.16"), ("4.1", "4.1.10"), ("5.0", "5.0.6")]}
        self.save_matrix()
        self.git("init", "-q")
        self.git("remote", "add", "origin", "https://github.com/example/cassandra-ldap.git")
        self.seal()
        now = time.time()
        for module in self.matrix:
            self.write_jar(module)
            os.utime(self.jar(module), (now, now))
        self.unit = self.write("cassandra-4.1/target/surefire-reports/TEST-TestSuite.xml", self.xml(18))
        os.utime(self.unit, (now + 1, now + 1))

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def seal(self):
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.org",
                 "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "Synthetic fixture")
        self.commit = self.git("rev-parse", "HEAD")
        self.git("-c", "tag.gpgsign=false", "tag", "-f", "v1.2.0")

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def jar(self, module):
        return self.root / f'cassandra-{module}/target/cassandra-ldap-{self.matrix[module]["version"]}-1.2.0.jar'

    def write_jar(self, module, embedded_version="1.2.0", omit=None, extra=None):
        path = self.jar(module)
        path.parent.mkdir(parents=True, exist_ok=True)
        names = ["com/instaclustr/cassandra/ldap/auth/LdapAccessSync.class",
                 "com/instaclustr/cassandra/ldap/conf/LdapSecretResolver.class",
                 "org/apache/cassandra/auth/LDAPCassandraRoleManager.class"]
        with zipfile.ZipFile(path, "w") as jar:
            for name in names:
                if name != omit:
                    jar.writestr(name, b"fixture")
            jar.writestr(f'META-INF/maven/com.instaclustr/cassandra-ldap-{self.matrix[module]["version"]}/pom.properties',
                         "version=" + embedded_version + "\n")
            if extra:
                jar.writestr(extra, b"fixture")

    def xml(self, count, failures=0, skipped=0):
        return (f'<testsuite tests="{count}" failures="{failures}" errors="0" skipped="{skipped}">'
                + "<testcase/>" * count + "</testsuite>")

    def save_matrix(self):
        self.write("molecule/integration/matrix.json", json.dumps(self.matrix))

    def test_packages_only_public_verified_assets(self):
        previous_umask = os.umask(0o077)
        try:
            target = prepare_release(self.root, "v1.2.0")
        finally:
            os.umask(previous_umask)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o755)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in target.iterdir()))
        self.assertEqual(len(list(target.iterdir())), 10)
        manifest = json.loads((target / "release-manifest.json").read_text())
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["commit"], self.commit)
        self.assertEqual(manifest["verification"]["java_unit_tests"]["tests"], 18)
        self.assertEqual(manifest["verification"]["cluster_e2e"],
                         {"status": "not_run_by_release_pipeline", "execution": "local_only"})
        self.assertNotIn("e2e_tests", json.dumps(manifest))
        self.assertEqual(len(manifest["artifacts"]), 6)
        self.assertNotIn(str(self.root), json.dumps(manifest))
        for line in (target / "SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ")
            self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), expected)
        with zipfile.ZipFile(target / "cassandra-ldap-1.2.0.zip") as bundle:
            prefix = "cassandra-ldap-1.2.0/"
            self.assertIn(prefix + "conf/ldap.yaml", bundle.namelist())
            self.assertIn(prefix + "CHANGELOG.md", bundle.namelist())
            guide = bundle.read(prefix + "SECRET_HANDLING.md").decode()
            self.assertIn("/blob/v1.2.0/molecule/integration/README.md)", guide)
            self.assertNotIn("](molecule/", guide)
            self.assertFalse(any(".state" in name or "results.xml" in name for name in bundle.namelist()))
            for line in bundle.read(prefix + "SHA256SUMS").decode().splitlines():
                expected, name = line.split("  ")
                self.assertEqual(hashlib.sha256(bundle.read(prefix + name)).hexdigest(), expected)
        notes = (target / "RELEASE_NOTES.md").read_text()
        self.assertIn("does not start Cassandra", notes)
        self.assertNotIn("15/15", notes)
        self.assertIn("Current fixture change", notes)
        self.assertNotIn("Old fixture change", notes)
        self.assertNotIn("## Access Model", notes)
        self.assertIn("/blob/v1.2.0/ACCESS_SYNC.md#bind-identity-access-review", notes)

    def test_rejects_missing_changelog(self):
        (self.root / 'CHANGELOG.md').unlink()
        self.seal()
        with self.assertRaises(FileNotFoundError):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_missing_release_entry(self):
        self.write('CHANGELOG.md', '# Changelog\n\n## 1.1.0 - 2026-01-01\n\n- Old change.\n')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'exactly one dated entry'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_duplicate_release_entry(self):
        self.write('CHANGELOG.md', '## 1.2.0 - 2026-11-05\n\n- One.\n\n## 1.2.0 - 2026-11-05\n\n- Two.\n')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'exactly one dated entry'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_empty_release_entry(self):
        self.write('CHANGELOG.md', '## 1.2.0 - 2026-11-05\n\n## 1.1.0 - 2026-01-01\n\n- Old.\n')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'must contain changes'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_invalid_release_date(self):
        self.write('CHANGELOG.md', '## 1.2.0 - 2026-13-05\n\n- Change.\n')
        self.seal()
        with self.assertRaises(ValueError):
            prepare_release(self.root, 'v1.2.0')

    def test_ignores_local_e2e_reports(self):
        self.write("molecule/integration/.state/reports/summary.json", "invalid JSON is deliberately ignored")
        target = prepare_release(self.root, "v1.2.0")
        manifest = json.loads((target / "release-manifest.json").read_text())
        self.assertEqual(manifest["verification"]["cluster_e2e"]["execution"], "local_only")

    def test_rejects_unshaded_jar(self):
        self.write_jar("4.1", omit="com/instaclustr/cassandra/ldap/conf/LdapSecretResolver.class")
        with self.assertRaisesRegex(ValueError, "not the shaded plugin"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_bundled_server_dependencies(self):
        self.write_jar("4.1", extra="org/yaml/snakeyaml/Yaml.class")
        with self.assertRaisesRegex(ValueError, "bundles a server dependency"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_wrong_embedded_version(self):
        self.write_jar("4.1", embedded_version="0.0.0")
        with self.assertRaisesRegex(ValueError, "embedded Maven version"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_wrong_release_version(self):
        with self.assertRaisesRegex(ValueError, "Maven release version"):
            prepare_release(self.root, "v1.2.1")

    def test_rejects_wrong_adapter_version(self):
        self.matrix["4.1"]["plugin_version"] = "0.0.0"
        self.save_matrix()
        self.seal()
        with self.assertRaisesRegex(ValueError, "Adapter artifact versions"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_incomplete_matrix(self):
        del self.matrix["2.2"]
        self.save_matrix()
        self.seal()
        with self.assertRaisesRegex(ValueError, "all six Cassandra adapters"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_dirty_source(self):
        self.write("uncommitted.txt", "fixture")
        with self.assertRaisesRegex(ValueError, "source tree must be clean"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_tag_not_at_head(self):
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.org",
                 "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "Another fixture commit")
        with self.assertRaisesRegex(ValueError, "tag must point to HEAD"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_missing_unit_report(self):
        self.unit.unlink()
        with self.assertRaises(FileNotFoundError):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_failed_unit_tests(self):
        self.unit.write_text(self.xml(18, failures=1))
        with self.assertRaisesRegex(ValueError, "Failed, skipped or incomplete"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_skipped_unit_tests(self):
        self.unit.write_text(self.xml(18, skipped=1))
        with self.assertRaisesRegex(ValueError, "Failed, skipped or incomplete"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_stale_unit_report(self):
        os.utime(self.unit, (1, 1))
        with self.assertRaisesRegex(ValueError, "after packaging jars"):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_missing_jar(self):
        self.jar("4.1").unlink()
        with self.assertRaises(FileNotFoundError):
            prepare_release(self.root, "v1.2.0")

    def test_rejects_existing_output(self):
        (self.root / "dist/v1.2.0").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "output already exists"):
            prepare_release(self.root, "v1.2.0")


if __name__ == "__main__":
    unittest.main()
