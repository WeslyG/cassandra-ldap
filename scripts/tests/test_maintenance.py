"""Maintenance coordination without Docker, LDAP or a running Cassandra server."""
import contextlib
import pathlib
import sys
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'molecule/integration'))
import harness


class MaintenanceTest(unittest.TestCase):
    def setUp(self):
        self.owner = None
        self.lose_reply = False
        self.release_attempts = 0

    @contextlib.contextmanager
    def connection(self):
        yield self

    def execute(self, query, parameters=None):
        if not isinstance(query, str):
            self.assertEqual(query.consistency_level, harness.ConsistencyLevel.SERIAL)
            row = SimpleNamespace(owner=self.owner)
        elif 'SET owner=null' in query:
            self.release_attempts += 1
            applied = self.owner == parameters[0]
            if applied:
                self.owner = None
            row = SimpleNamespace(applied=applied)
        else:
            applied = self.owner is None
            if applied:
                self.owner = parameters[0]
            if self.lose_reply:
                self.lose_reply = False
                raise TimeoutError('Synthetic lost CAS reply')
            row = SimpleNamespace(applied=applied)
        return SimpleNamespace(one=lambda: row)

    def once(self, operation):
        operation()

    def test_reserves_and_releases_own_lock(self):
        with patch.object(harness, 'connection', self.connection), patch.object(harness, 'eventually', self.once):
            with harness.maintenance() as owner:
                self.assertEqual(self.owner, owner)
            self.assertIsNone(self.owner)

    def test_does_not_steal_existing_owner(self):
        existing = self.owner = uuid.uuid4()
        with patch.object(harness, 'connection', self.connection), patch.object(harness, 'eventually', self.once):
            with self.assertRaisesRegex(AssertionError, 'another writer'):
                with harness.maintenance():
                    self.fail('Must not enter another owner\'s critical section')
        self.assertEqual(self.owner, existing)
        self.assertEqual(self.release_attempts, 0)

    def test_resolves_lost_cas_reply(self):
        self.lose_reply = True
        with patch.object(harness, 'connection', self.connection), patch.object(harness, 'eventually', self.once):
            with harness.maintenance() as owner:
                self.assertEqual(self.owner, owner)
            self.assertIsNone(self.owner)

    def test_releases_own_lock_after_body_failure(self):
        with patch.object(harness, 'connection', self.connection), patch.object(harness, 'eventually', self.once):
            with self.assertRaisesRegex(RuntimeError, 'Synthetic body failure'):
                with harness.maintenance():
                    raise RuntimeError('Synthetic body failure')
            self.assertIsNone(self.owner)

    def test_refuses_to_clear_changed_owner(self):
        other = uuid.uuid4()
        with patch.object(harness, 'connection', self.connection), patch.object(harness, 'eventually', self.once):
            with self.assertRaisesRegex(AssertionError, 'refusing to clear another owner'):
                with harness.maintenance():
                    self.owner = other
        self.assertEqual(self.owner, other)
