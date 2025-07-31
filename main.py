# LumenTrace: Automated Wake-on-LAN for UPS Power Restoration
# Copyright (C) 2025 Patrick Smith patricksmith0330@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the
# Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# LumenTrace: Automated Wake-on-LAN for UPS Power Restoration
# Copyright (C) 2025 Patrick Smith patricksmith0330@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the
# Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import os
import logging
import sys
from dotenv import load_dotenv
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from waitress import serve
from pythonjsonlogger import jsonlogger

load_dotenv()

from config import FLASK_CONFIG, DATA_DIR, POLL_INTERVAL
from models import state_manager
from services.monitoring import MonitoringService
from routes import register_blueprints

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

app = Flask(__name__)
app.config.update(FLASK_CONFIG)

for handler in list(app.logger.handlers):
    app.logger.removeHandler(handler)

app.logger.addHandler(logHandler)
app.logger.setLevel(logging.INFO)

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://" 
)

app.limiter = limiter

register_blueprints(app)

monitoring_service = MonitoringService(state_manager, POLL_INTERVAL)

app.state_manager = state_manager

if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    
    with app.app_context():
        state_manager.load()

    monitoring_service.start()
    
    logger.info("Starting LumenTrace server on port 5000...")
    serve(app, host='0.0.0.0', port=5000, threads=10)