import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import models
from config import DEFAULT_STATE
from models import StateManager
from services.monitoring import MonitoringService


class MonitoringRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        data_dir = Path(self.temporary_directory.name)
        self.data_file_patch = patch.object(models, 'DATA_FILE', str(data_dir / 'state.json'))
        self.lock_file_patch = patch.object(models, 'DATA_LOCK_FILE', str(data_dir / 'state.lock'))
        self.data_file_patch.start()
        self.lock_file_patch.start()

        self.manager = StateManager()
        self.manager.state = copy.deepcopy(DEFAULT_STATE)
        self.manager.state['settings']['ups_configs'] = [
            {'id': 'ups-1', 'name': 'ups', 'ip': '192.168.1.20', 'port': 3493}
        ]
        self.manager.state['settings']['wol_battery_threshold'] = 80
        self.manager.state['devices'] = [
            {'name': 'Server', 'ip': '192.168.1.10', 'mac': 'AA:BB:CC:DD:EE:FF', 'online': True}
        ]
        self.service = MonitoringService(self.manager, poll_interval=1)

    def tearDown(self):
        self.lock_file_patch.stop()
        self.data_file_patch.stop()
        self.temporary_directory.cleanup()

    @patch('services.monitoring.update_uptime_stats')
    @patch('services.monitoring.send_wol')
    @patch('services.monitoring.is_device_online', return_value=True)
    @patch('services.monitoring.get_ups_data')
    def test_waits_for_recharge_after_power_returns(self, get_ups_data, _online, send_wol, _uptime):
        get_ups_data.side_effect = [
            [{'id': 'ups-1', 'name': 'ups', 'status': 'OB', 'battery': 45}],
            [{'id': 'ups-1', 'name': 'ups', 'status': 'OL', 'battery': 60}],
            [{'id': 'ups-1', 'name': 'ups', 'status': 'OL', 'battery': 85}],
        ]

        self.service._check_status()
        self.assertEqual(self.manager.state['recovery_state'], 'OUTAGE_CAPTURED')
        self.assertEqual(self.manager.state['outage_snapshot'], ['AA:BB:CC:DD:EE:FF'])

        self.service._check_status()
        self.assertEqual(self.manager.state['recovery_state'], 'WAITING_FOR_RECHARGE')
        send_wol.assert_not_called()

        self.service._check_status()
        send_wol.assert_called_once_with('AA:BB:CC:DD:EE:FF', self.manager)
        self.assertEqual(self.manager.state['recovery_state'], 'NORMAL')
        self.assertEqual(self.manager.state['outage_snapshot'], [])

    @patch('services.monitoring.update_uptime_stats')
    @patch('services.monitoring.send_wol')
    @patch('services.monitoring.is_device_online', return_value=True)
    @patch('services.monitoring.get_ups_data')
    def test_multi_ups_mixed_state_does_not_lose_recovery(self, get_ups_data, _online, send_wol, _uptime):
        self.manager.state['settings']['ups_configs'].append(
            {'id': 'ups-2', 'name': 'ups2', 'ip': '192.168.1.21', 'port': 3493}
        )
        get_ups_data.side_effect = [
            [
                {'id': 'ups-1', 'name': 'ups', 'status': 'OB', 'battery': 70},
                {'id': 'ups-2', 'name': 'ups2', 'status': 'OB', 'battery': 70},
            ],
            [
                {'id': 'ups-1', 'name': 'ups', 'status': 'OL', 'battery': 90},
                {'id': 'ups-2', 'name': 'ups2', 'status': 'OB', 'battery': 72},
            ],
            [
                {'id': 'ups-1', 'name': 'ups', 'status': 'OL', 'battery': 90},
                {'id': 'ups-2', 'name': 'ups2', 'status': 'OL', 'battery': 90},
            ],
        ]

        self.service._check_status()
        self.service._check_status()
        send_wol.assert_not_called()
        self.assertEqual(self.manager.state['recovery_state'], 'OUTAGE_CAPTURED')

        self.service._check_status()
        send_wol.assert_called_once()
        self.assertEqual(self.manager.state['recovery_state'], 'NORMAL')


class StateStorageTests(unittest.TestCase):
    def test_save_is_atomic_and_retains_backup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_file = Path(temporary_directory) / 'state.json'
            lock_file = Path(temporary_directory) / 'state.lock'
            with patch.object(models, 'DATA_FILE', str(state_file)), patch.object(models, 'DATA_LOCK_FILE', str(lock_file)):
                manager = StateManager()
                manager.state['last_status'] = 'OL'
                manager.save()
                manager.state['last_status'] = 'OB'
                manager.save()

                self.assertEqual(json.loads(state_file.read_text())['last_status'], 'OB')
                self.assertEqual(json.loads(Path(f'{state_file}.bak').read_text())['last_status'], 'OL')


if __name__ == '__main__':
    unittest.main()
