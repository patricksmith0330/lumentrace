import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
import models
from models import StateManager


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        data_dir = Path(self.temporary_directory.name)
        self.patches = [
            patch.object(main, 'DATA_DIR', str(data_dir)),
            patch.object(main, 'state_manager', StateManager()),
            patch.object(models, 'DATA_FILE', str(data_dir / 'state.json')),
            patch.object(models, 'DATA_LOCK_FILE', str(data_dir / 'state.lock')),
        ]
        for active_patch in self.patches:
            active_patch.start()
        self.app = main.create_app({
            'TESTING': True,
            'SECRET_KEY': 'test-secret',
            'AUTH_MODE': 'local',
            'AUTH_DB_PATH': str(data_dir / 'auth.db'),
            'WTF_CSRF_ENABLED': False,
            'RATELIMIT_ENABLED': False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.temporary_directory.cleanup()

    def create_admin(self):
        return self.app.auth_store.create_user(
            'admin',
            'correct horse battery staple',
            'Administrator',
            'admin',
        )

    def login(self, username='admin', password='correct horse battery staple'):
        return self.client.post('/login', data={
            'username': username,
            'password': password,
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
            'password': 'correct horse battery staple',
            'password_confirm': 'correct horse battery staple',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/')
        dashboard = self.client.get('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.headers['Cache-Control'], 'no-store')
        self.assertEqual(dashboard.headers['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", dashboard.headers['Content-Security-Policy'])
        self.assertTrue(self.app.auth_store.get_by_username('admin').password_hash.startswith('scrypt:'))
        with self.assertRaisesRegex(ValueError, 'already been completed'):
            self.app.auth_store.create_initial_admin(
                'second-admin',
                'another sufficiently long password',
            )

    def test_login_logout_and_safe_redirect(self):
        self.create_admin()
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('/login?next='))

        response = self.client.post('/login?next=https://example.com', data={
            'username': 'admin',
            'password': 'correct horse battery staple',
            'next': 'https://example.com',
        })
        self.assertEqual(response.headers['Location'], '/')
        self.assertEqual(self.client.get('/api/dashboard').status_code, 200)

        response = self.client.post('/logout')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/api/dashboard').status_code, 401)

    def test_viewer_is_read_only(self):
        self.create_admin()
        self.app.auth_store.create_user(
            'observer',
            'viewer password is long enough',
            'Observer',
            'viewer',
        )
        self.login('observer', 'viewer password is long enough')
        dashboard = self.client.get('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn(b'Scan network', dashboard.data)
        self.assertEqual(self.client.get('/discover').status_code, 403)
        self.assertIn(
            b'<fieldset class="settings-readonly" disabled>',
            self.client.get('/settings').data,
        )
        self.assertEqual(self.client.post('/settings', data={}).status_code, 403)
        api_response = self.client.post('/api/ups', json={})
        self.assertEqual(api_response.status_code, 403)
        self.assertEqual(api_response.get_json()['message'], 'Administrator access is required.')

    def test_password_reset_invalidates_existing_session(self):
        user = self.create_admin()
        self.login()
        self.assertEqual(self.client.get('/').status_code, 200)
        self.app.auth_store.set_password(user.id, 'a completely different password')
        self.assertEqual(self.client.get('/api/dashboard').status_code, 401)

    def test_failed_login_and_account_creation_are_audited(self):
        self.create_admin()
        self.client.post('/login', data={'username': 'admin', 'password': 'wrong password'})
        self.login()
        response = self.client.post('/users', data={
            'display_name': 'Read only',
            'username': 'readonly',
            'role': 'viewer',
            'password': 'another suitably long password',
            'password_confirm': 'another suitably long password',
        })
        self.assertEqual(response.status_code, 302)
        events = self.app.auth_store.list_audit_events()
        event_types = {event['event_type'] for event in events}
        self.assertIn('auth.login_failed', event_types)
        self.assertIn('account.created', event_types)

    def test_cli_password_recovery(self):
        self.create_admin()
        runner = self.app.test_cli_runner()
        result = runner.invoke(
            args=['auth', 'reset-password', 'admin'],
            input='replacement password is long\nreplacement password is long\n',
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNotNone(
            self.app.auth_store.verify_user('admin', 'replacement password is long')
        )


if __name__ == '__main__':
    unittest.main()
