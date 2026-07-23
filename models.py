import json
import os
import logging
import uuid
import copy
import shutil
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from filelock import FileLock
from config import DATA_FILE, DATA_LOCK_FILE, DEFAULT_STATE, DEFAULT_SETTINGS

logger = logging.getLogger(__name__)

class StateManager:
    
    def __init__(self):
        self.state = copy.deepcopy(DEFAULT_STATE)
        self.lock_timeout = 10
        self._memory_lock = threading.RLock()
        
    def load(self):
        os.makedirs(os.path.dirname(DATA_LOCK_FILE) or '.', exist_ok=True)
        with self._memory_lock, FileLock(DATA_LOCK_FILE, timeout=self.lock_timeout):
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, 'r') as f:
                        loaded_state = json.load(f)
                        self.state = copy.deepcopy(DEFAULT_STATE)
                        self.state.update(loaded_state)
                        self.state['settings'] = {
                            **copy.deepcopy(DEFAULT_SETTINGS),
                            **self.state.get('settings', {})
                        }
                        
                        for ups in self.state['settings']['ups_configs']:
                            if 'id' not in ups:
                                ups['id'] = generate_ups_id(ups['name'], ups['ip'])
                        
                        for device in self.state.get('devices', []):
                            device.setdefault('last_seen', None)
                            
                    logger.info(f"Loaded state from {DATA_FILE}")
                except (json.JSONDecodeError, Exception) as e:
                    logger.error(f"Error loading state: {e}. Using default state.")
                    self.state = copy.deepcopy(DEFAULT_STATE)
                    self._save_unlocked()
            else:
                logger.info("No state file found, initializing with default state.")
                self.state = copy.deepcopy(DEFAULT_STATE)
                self._save_unlocked()
    
    def _save_unlocked(self):
        try:
            data_dir = os.path.dirname(DATA_FILE)
            os.makedirs(data_dir, exist_ok=True)
            if os.path.exists(DATA_FILE):
                shutil.copy2(DATA_FILE, f"{DATA_FILE}.bak")

            fd, temporary_path = tempfile.mkstemp(prefix='state-', suffix='.tmp', dir=data_dir)
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(self.state, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temporary_path, DATA_FILE)
            finally:
                if os.path.exists(temporary_path):
                    os.unlink(temporary_path)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def save(self):
        os.makedirs(os.path.dirname(DATA_LOCK_FILE) or '.', exist_ok=True)
        with self._memory_lock, FileLock(DATA_LOCK_FILE, timeout=self.lock_timeout):
            self._save_unlocked()

    @contextmanager
    def locked(self):
        """Serialize in-memory mutations made by requests and the monitor."""
        with self._memory_lock:
            yield self.state

    def snapshot(self):
        with self._memory_lock:
            return copy.deepcopy(self.state)
    
    def get(self, key, default=None):
        return self.state.get(key, default)
    
    def set(self, key, value):
        self.state[key] = value
    
    def add_log(self, message, level='INFO'):
        current_time = datetime.now(timezone.utc).isoformat(timespec='seconds')
        log_method = getattr(logger, level.lower(), logger.info)
        log_method(message, extra={'log_type': 'app_event', 'event': message})
        
        with self._memory_lock:
            self.state['logs'].append({
                'time': current_time,
                'message': message,
                'level': level
            })
            max_logs = self.state.get('settings', {}).get('log_retention', 100)
            self.state['logs'] = self.state['logs'][-max_logs:]
            self.save()
    
    def add_event(self, event_type, description, details=None):
        now = datetime.now(timezone.utc)
        event = {
            'timestamp': now.timestamp(),
            'type': event_type,
            'description': description,
            'details': details or {},
            'time_str': now.isoformat(timespec='seconds')
        }
        with self._memory_lock:
            self.state['event_timeline'].append(event)
            self.state['event_timeline'] = self.state['event_timeline'][-500:]
            self.save()


def generate_ups_id(name, ip):
    return f"{name}_{ip}_{str(uuid.uuid4())[:8]}"


def find_ups_by_id(state, ups_id):
    for i, ups in enumerate(state.get('settings', {}).get('ups_configs', [])):
        if ups.get('id') == ups_id:
            return i, ups
    return None, None


state_manager = StateManager()
