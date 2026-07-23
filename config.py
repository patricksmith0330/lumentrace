import os


SECRET_KEY = os.getenv('SECRET_KEY')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 10))
DATA_DIR = os.environ.get('DATA_DIR', '/data')

DATA_FILE = os.path.join(DATA_DIR, 'state.json')
DATA_LOCK_FILE = os.path.join(DATA_DIR, 'state.lock')
DATABASE_PATH = os.path.join(DATA_DIR, 'lumentrace.db')
LEGACY_AUTH_DB_PATH = os.path.join(DATA_DIR, 'auth.db')

CACHE_TTL = 5  # seconds

DEFAULT_SETTINGS = {
    'refresh_interval': 30,
    'log_retention': 100,
    'ip_scan_range': '192.168.1.0/24',
    'discovery_timeout': 2,
    'ups_configs': [],
    'wol_battery_threshold': 80,
    'verbose_logging': False,
}

DEFAULT_STATE = {
    'devices': [],
    'settings': DEFAULT_SETTINGS,
    'last_status': '',
    'recovery_state': 'NORMAL',
    'outage_snapshot': [],
    'logs': [],
    'battery_history': [],
    'uptime_stats': {},
    'event_timeline': []
}

RATE_LIMITS = {
    'login': "10 per minute",
    'setup': "5 per hour",
    'api_write': "5 per minute",
    'api_read': "60 per minute",
    'device_action': "10 per minute",
    'discovery': "2 per minute"
}
