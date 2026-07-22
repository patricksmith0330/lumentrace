import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
import models
from models import StateManager


class AppSmokeTests(unittest.TestCase):
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
            'WTF_CSRF_ENABLED': False,
            'RATELIMIT_ENABLED': False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.temporary_directory.cleanup()

    def test_primary_pages_render(self):
        for path in ['/', '/discover', '/settings', '/add_device', '/api/health']:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_add_device_and_dashboard_api(self):
        response = self.client.post('/add_device', data={
            'name': 'Server',
            'ip': '192.168.1.10',
            'mac': 'AA:BB:CC:DD:EE:FF',
        })
        self.assertEqual(response.status_code, 302)

        payload = self.client.get('/api/dashboard').get_json()
        self.assertEqual(payload['devices'][0]['name'], 'Server')
        self.assertEqual(payload['recovery_state'], 'NORMAL')

    def test_settings_validation_and_save(self):
        response = self.client.post('/settings', data={
            'refresh_interval': '20',
            'log_retention': '200',
            'wol_battery_threshold': '85',
            'discovery_timeout': '3',
            'ip_scan_range': '10.0.0.0/24',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.app.state_manager.get('settings')['wol_battery_threshold'], 85)


if __name__ == '__main__':
    unittest.main()
