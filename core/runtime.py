import threading

from config import POLL_INTERVAL
from models import state_manager
from services.monitoring import MonitoringService


manager = state_manager
monitoring_service = MonitoringService(manager, POLL_INTERVAL)
_initialization_lock = threading.Lock()
_initialized = False
_monitoring_started = False


def initialize(start_monitoring=False):
    global _initialized, _monitoring_started
    with _initialization_lock:
        if not _initialized:
            manager.load()
            _initialized = True
        if start_monitoring and not _monitoring_started:
            monitoring_service.start()
            _monitoring_started = True
