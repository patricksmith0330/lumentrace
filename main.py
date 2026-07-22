import os
import logging
import sys
from dotenv import load_dotenv
from flask import Flask
from waitress import serve
from pythonjsonlogger import jsonlogger

load_dotenv()

from config import FLASK_CONFIG, DATA_DIR, POLL_INTERVAL
from models import state_manager
from services.monitoring import MonitoringService
from routes import register_blueprints
from extensions import csrf, limiter

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logHandler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s'
)
logHandler.setFormatter(formatter)

if logger.hasHandlers():
    logger.handlers.clear()
logger.addHandler(logHandler)

def create_app(test_config=None, start_monitoring=False):
    app = Flask(__name__)
    app.config.update(FLASK_CONFIG)
    if test_config:
        app.config.update(test_config)

    if not app.config.get('TESTING') and not app.config.get('SECRET_KEY'):
        raise RuntimeError('SECRET_KEY must be set to a long, random value.')

    for handler in list(app.logger.handlers):
        app.logger.removeHandler(handler)
    app.logger.addHandler(logHandler)
    app.logger.setLevel(logging.INFO)

    csrf.init_app(app)
    limiter.init_app(app)
    register_blueprints(app)

    os.makedirs(DATA_DIR, exist_ok=True)
    state_manager.load()
    app.state_manager = state_manager
    app.monitoring_service = MonitoringService(state_manager, POLL_INTERVAL)

    if start_monitoring:
        app.monitoring_service.start()

    return app

if __name__ == '__main__':
    app = create_app(start_monitoring=True)
    logger.info("Starting LumenTrace server on port 5000...")
    serve(app, host='0.0.0.0', port=5000, threads=10)
