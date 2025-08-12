import os
from pathlib import Path

SECRET_KEY = os.getenv('SECRET_KEY', 'dev_secret_fallback')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 10))
DATA_DIR = os.environ.get('DATA_DIR', '/data')

DATA_FILE = os.path.join(DATA_DIR, 'state.json')
DATA_LOCK_FILE = os.path.join(DATA_DIR, 'state.lock')

CACHE_TTL = 5  # seconds

DEFAULT_SETTINGS = {
    'refresh_interval': 30,
    'log_retention': 100,
    'ip_scan_range': '192.168.1.0/24',
    'discovery_timeout': 2,
    'ups_configs': [],
    'density': 'comfortable',
    'wol_battery_threshold': 80,
    'verbose_logging': False,
    'theme': 'dark'
}

DEFAULT_STATE = {
    'devices': [],
    'settings': DEFAULT_SETTINGS,
    'last_status': '',
    'outage_snapshot': [],
    'logs': [],
    'battery_history': [],
    'uptime_stats': {},
    'event_timeline': []
}

FLASK_CONFIG = {
    'SECRET_KEY': SECRET_KEY,
    'TEMPLATES_AUTO_RELOAD': True
}

RATE_LIMITS = {
    'api_write': "5 per minute",
    'api_read': "60 per minute",
    'device_action': "10 per minute",
    'discovery': "2 per minute"
}