import json
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from werkzeug.security import generate_password_hash

from core.auth_utils import create_user
from core.models import AuditEvent


@override_settings(AUTH_MODE='local', RATELIMIT_ENABLED=False)
class AuthenticationFlowTests(TestCase):
    password = 'violet-orbit-river-copper-4821'

    def create_admin(self):
        return create_user('admin', self.password, 'Administrator', 'admin')

    def login(self, username='admin', password=None):
        return self.client.post('/login', data={
            'username': username,
            'password': password or self.password,
        })

    def test_first_run_requires_administrator_setup(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/setup')
        self.assertEqual(self.client.get('/api/health').status_code, 200)
        self.assertEqual(self.client.get('/api/dashboard').status_code, 503)

        response = self.client.post('/setup', data={
            'display_name': 'Administrator',
            'username': 'admin',
            'password': self.password,
            'password_confirm': self.password,
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/')
        dashboard = self.client.get('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.headers['Cache-Control'], 'no-store')
        user = get_user_model().objects.get(username='admin')
        self.assertTrue(user.password.startswith('scrypt$'))
        self.assertTrue(user.is_staff)

    def test_login_logout_and_safe_redirect(self):
        self.create_admin()
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('/login?next='))
        response = self.client.post('/login?next=https://example.com', data={
            'username': 'admin',
            'password': self.password,
            'next': 'https://example.com',
        })
        self.assertEqual(response.headers['Location'], '/')
        self.assertEqual(self.client.get('/api/dashboard').status_code, 200)
        self.assertEqual(self.client.post('/logout').status_code, 302)
        self.assertEqual(self.client.get('/api/dashboard').status_code, 401)

    def test_viewer_is_read_only(self):
        self.create_admin()
        create_user(
            'observer',
            'amber-forest-window-harbor-9234',
            'Observer',
            'viewer',
        )
        self.login('observer', 'amber-forest-window-harbor-9234')
        dashboard = self.client.get('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotContains(dashboard, 'Scan network')
        self.assertEqual(self.client.get('/discover').status_code, 403)
        self.assertIn(
            b'<fieldset class="settings-readonly" disabled>',
            self.client.get('/settings').content,
        )
        self.assertEqual(self.client.post('/settings', data={}).status_code, 403)
        api_response = self.client.post(
            '/api/ups',
            data=json.dumps({}),
            content_type='application/json',
        )
        self.assertEqual(api_response.status_code, 403)
        self.assertEqual(api_response.json()['message'], 'Administrator access is required.')

    def test_password_reset_invalidates_existing_session(self):
        user = self.create_admin()
        self.login()
        session_cookie = self.client.cookies['lumentrace_session'].value
        user.set_password('coral-station-glass-meadow-7751')
        user.save(update_fields=['password'])
        self.client.cookies['lumentrace_session'] = session_cookie
        self.assertEqual(self.client.get('/api/dashboard').status_code, 401)

    def test_failed_login_and_account_creation_are_audited(self):
        self.create_admin()
        self.client.post('/login', data={'username': 'admin', 'password': 'wrong password'})
        self.login()
        response = self.client.post('/users', data={
            'display_name': 'Read only',
            'username': 'readonly',
            'role': 'viewer',
            'password': 'bright-canyon-paper-signal-3372',
            'password_confirm': 'bright-canyon-paper-signal-3372',
        })
        self.assertEqual(response.status_code, 302)
        event_types = set(AuditEvent.objects.values_list('event_type', flat=True))
        self.assertIn('auth.login_failed', event_types)
        self.assertIn('account.created', event_types)


@override_settings(AUTH_MODE='local', RATELIMIT_ENABLED=False)
class FlaskAccountMigrationTests(TestCase):
    def test_imported_password_is_accepted_and_upgraded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            legacy_path = Path(temporary_directory) / 'auth.db'
            connection = sqlite3.connect(legacy_path)
            connection.executescript(
                '''
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT,
                    session_version INTEGER NOT NULL
                );
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    actor_user_id TEXT,
                    actor_username TEXT,
                    event_type TEXT NOT NULL,
                    target TEXT,
                    details TEXT NOT NULL,
                    remote_address TEXT
                );
                '''
            )
            old_hash = generate_password_hash(
                'legacy-password-copper-9931',
                method='scrypt',
            )
            connection.execute(
                'INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    'legacy-id',
                    'legacyadmin',
                    'Legacy Administrator',
                    old_hash,
                    'admin',
                    1,
                    '2026-01-01T00:00:00+00:00',
                    None,
                    1,
                ),
            )
            connection.commit()
            connection.close()

            with patch.dict(os.environ, {'LEGACY_AUTH_DB_PATH': str(legacy_path)}):
                call_command('migrate_flask_auth', verbosity=0)

            user = get_user_model().objects.get(username='legacyadmin')
            self.assertEqual(user.password, old_hash)
            response = self.client.post('/login', data={
                'username': 'legacyadmin',
                'password': 'legacy-password-copper-9931',
            })
            self.assertEqual(response.status_code, 302)
            user.refresh_from_db()
            self.assertTrue(user.password.startswith('scrypt$'))
