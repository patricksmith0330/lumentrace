from routes.api import api_bp
from routes.dashboard import dashboard_bp
from routes.devices import devices_bp
from routes.settings import settings_bp

def register_blueprints(app):
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(settings_bp)