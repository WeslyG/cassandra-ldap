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
        self.scenario = self.root / 'molecule/integration'
        self.reports = self.scenario / '.state/reports'
        self.write('.gitignore', '**/target/\nmolecule/integration/.state/\ndist/\n')
        self.write('pom.xml', '<project xmlns="http://maven.apache.org/POM/4.0.0"><version>1.2.0</version></project>')
        self.write('conf/ldap.yaml', 'ldap_service_password: REPLACE_WITH_SECRET\n')
        self.write('conf/access-sync-schema.cql', '-- Synthetic schema fixture\n')
        self.write('LICENSE', 'Synthetic license fixture\n')
        self.matrix = {module: {'version': server, 'plugin_version': '1.2.0'} for module, server in
                       [('2.2', '2.2.19'), ('3.0', '3.0.31'), ('3.11', '3.11.18'),
                        ('4.0', '4.0.16'), ('4.1', '4.1.10'), ('5.0', '5.0.6')]}
        self.write('molecule/integration/matrix.json', json.dumps(self.matrix))
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.org',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic release fixture')
        self.commit = self.git('rev-parse', 'HEAD')
        self.git('-c', 'tag.gpgsign=false', 'tag', 'v1.2.0')
        self.git('remote', 'add', 'origin', 'https://github.com/example/cassandra-ldap.git')
        now = time.time()
        self.summary = {}
        for module, config in self.matrix.items():
            server = config['version']
            path = self.jar(module)
            path.parent.mkdir(parents=True)
            with zipfile.ZipFile(path, 'w') as jar:
                jar.writestr('com/instaclustr/cassandra/ldap/auth/LdapAccessSync.class', b'fixture')
                jar.writestr('org/apache/cassandra/auth/LDAPCassandraRoleManager.class', b'fixture')
                jar.writestr(f'META-INF/maven/com.instaclustr/cassandra-ldap-{server}/pom.properties', 'version=1.2.0\n')
            os.utime(path, (now, now))
            self.summary[server] = {'source_commit': self.commit, 'source_dirty': False,
                                    'run_id': 'a' * 32, 'exit_code': 0, 'tests': 15,
                                    'failures': 0, 'errors': 0, 'skipped': 0,
                                    'idempotence_passed': True, 'teardown_passed': True,
                                    'server_versions': {'cassandra1': server, 'cassandra2': server},
                                    'image': f'cassandra:{server}', 'platform': 'linux/arm64',
                                    'jar_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'started_at': now + 2}
            self.write(f'molecule/integration/.state/reports/{server}/results.xml', self.xml(15))
            self.write(f'molecule/integration/.state/reports/{server}/molecule.log',
                       'idempotence: Executed: Successful\ndestroy: Executed: Successful\n')
        self.unit = self.write('cassandra-4.1/target/surefire-reports/TEST-TestSuite.xml', self.xml(10))
        os.utime(self.unit, (now + 1, now + 1))
        self.save_summary()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True).strip()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def jar(self, module):
        return self.root / f'cassandra-{module}/target/cassandra-ldap-{self.matrix[module]["version"]}-1.2.0.jar'

    def xml(self, count):
        return f'<testsuite tests="{count}" failures="0" errors="0" skipped="0">' + '<testcase/>' * count + '</testsuite>'

    def save_summary(self):
        self.write('molecule/integration/.state/reports/summary.json', json.dumps(self.summary))

    def test_packages_only_public_verified_assets(self):
        target = prepare_release(self.root, 'v1.2.0')
        self.assertEqual(len(list(target.iterdir())), 10)
        manifest = json.loads((target / 'release-manifest.json').read_text())
        self.assertEqual(manifest['commit'], self.commit)
        self.assertEqual(manifest['verification']['e2e_tests'], 90)
        self.assertEqual(len(manifest['artifacts']), 6)
        self.assertNotIn(str(self.root), (target / 'release-manifest.json').read_text())
        for line in (target / 'SHA256SUMS').read_text().splitlines():
            expected, name = line.split('  ')
            self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), expected)
        with zipfile.ZipFile(target / 'cassandra-ldap-1.2.0.zip') as bundle:
            prefix = 'cassandra-ldap-1.2.0/'
            self.assertIn(prefix + 'conf/ldap.yaml', bundle.namelist())
            self.assertIn(prefix + 'INSTALL.md', bundle.namelist())
            self.assertFalse(any('.state' in name or 'results.xml' in name for name in bundle.namelist()))
            for line in bundle.read(prefix + 'SHA256SUMS').decode().splitlines():
                expected, name = line.split('  ')
                self.assertEqual(hashlib.sha256(bundle.read(prefix + name)).hexdigest(), expected)

    def test_rejects_changed_jar(self):
        with self.jar('4.1').open('ab') as jar:
            jar.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'differs from the tested artifact'):
            prepare_release(self.root, 'v1.2.0')
        self.assertFalse((self.root / 'dist/v1.2.0').exists())

    def test_rejects_skipped_e2e(self):
        self.summary['4.1.10']['skipped'] = 1
        self.save_summary()
        with self.assertRaisesRegex(ValueError, '15/15'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_wrong_actual_server(self):
        self.summary['4.1.10']['server_versions']['cassandra2'] = '4.0.16'
        self.save_summary()
        with self.assertRaisesRegex(ValueError, 'actual node versions'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_mixed_runs(self):
        self.summary['4.1.10']['run_id'] = 'b' * 32
        self.save_summary()
        with self.assertRaisesRegex(ValueError, 'Mixed e2e runs'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_dirty_e2e_source(self):
        self.summary['4.1.10']['source_dirty'] = True
        self.save_summary()
        with self.assertRaisesRegex(ValueError, 'this clean commit'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_other_source_commit(self):
        self.summary['4.1.10']['source_commit'] = '0' * 40
        self.save_summary()
        with self.assertRaisesRegex(ValueError, 'this clean commit'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_wrong_release_version(self):
        with self.assertRaisesRegex(ValueError, 'Maven release version'):
            prepare_release(self.root, 'v1.2.1')

    def test_rejects_stale_unit_report(self):
        os.utime(self.unit, (1, 1))
        with self.assertRaisesRegex(ValueError, 'after packaging jars'):
            prepare_release(self.root, 'v1.2.0')

    def test_rejects_missing_e2e_xml(self):
        (self.reports / '4.1.10/results.xml').unlink()
        with self.assertRaises(FileNotFoundError):
            prepare_release(self.root, 'v1.2.0')


if __name__ == '__main__':
    unittest.main()
