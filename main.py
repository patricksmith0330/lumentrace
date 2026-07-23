import os
import logging
import sys
from dotenv import load_dotenv
from flask import Flask, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for
from waitress import serve
from pythonjsonlogger import jsonlogger

load_dotenv()

from config import FLASK_CONFIG, DATA_DIR, POLL_INTERVAL
from models import state_manager
from services.monitoring import MonitoringService
from services.auth import AnonymousUser, AuthStore, auth_cli
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
    if app.config['AUTH_MODE'] not in {'local', 'disabled'}:
        raise RuntimeError('AUTH_MODE must be either local or disabled.')

    for handler in list(app.logger.handlers):
        app.logger.removeHandler(handler)
    app.logger.addHandler(logHandler)
    app.logger.setLevel(logging.INFO)

    os.makedirs(DATA_DIR, exist_ok=True)
    app.auth_store = AuthStore(app.config['AUTH_DB_PATH'])
    app.auth_store.initialize()

    csrf.init_app(app)
    limiter.init_app(app)
    register_blueprints(app)
    app.cli.add_command(auth_cli)

    def unauthorized():
        if request.path.startswith('/api/'):
            return jsonify(success=False, message='Authentication required.'), 401
        return redirect(url_for('auth.login', next=request.full_path.rstrip('?')))

    @app.before_request
    def enforce_authentication():
        g.current_user = AnonymousUser()
        user_id = session.get('user_id')
        if user_id:
            user = current_app.auth_store.get_user(user_id)
            if (
                user
                and user.active
                and user.session_version == session.get('session_version')
            ):
                g.current_user = user
            else:
                session.clear()
        if current_app.config['AUTH_MODE'] == 'disabled':
            return None
        if request.endpoint in {'static', 'api.health', 'auth.login', 'auth.setup'}:
            return None
        if not current_app.auth_store.has_users():
            if request.path.startswith('/api/'):
                return jsonify(success=False, message='Administrator setup is required.'), 503
            return redirect(url_for('auth.setup'))
        if not g.current_user.is_authenticated:
            return unauthorized()
        if (
            request.method not in {'GET', 'HEAD', 'OPTIONS'}
            and not g.current_user.is_admin
            and request.endpoint not in {'auth.logout', 'auth.account'}
        ):
            if request.path.startswith('/api/'):
                return jsonify(success=False, message='Administrator access is required.'), 403
            abort(403)
        return None

    @app.errorhandler(403)
    def forbidden(_error):
        if request.path.startswith('/api/'):
            return jsonify(success=False, message='Administrator access is required.'), 403
        return render_template('errors/403.html'), 403

    @app.context_processor
    def inject_current_user():
        user = getattr(g, 'current_user', AnonymousUser())
        return {
            'current_user': user,
            'can_manage': current_app.config['AUTH_MODE'] == 'disabled' or user.is_admin,
        }

    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        response.headers.setdefault(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=()',
        )
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'",
        )
        if (
            request.endpoint
            and request.endpoint != 'static'
            and (
                request.endpoint.startswith('auth.')
                or (
                    current_app.config['AUTH_MODE'] == 'local'
                    and g.current_user.is_authenticated
                )
            )
        ):
            response.headers['Cache-Control'] = 'no-store'
        if current_app.config.get('SESSION_COOKIE_SECURE'):
            response.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains',
            )
        if (
            current_app.config['AUTH_MODE'] == 'local'
            and request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}
            and request.endpoint
            and not request.endpoint.startswith('auth.')
            and g.current_user.is_authenticated
            and response.status_code < 400
        ):
            try:
                current_app.auth_store.add_audit_event(
                    'application.write',
                    actor=g.current_user,
                    target=request.endpoint,
                    details={'method': request.method, 'status': response.status_code},
                    remote_address=request.remote_addr,
                )
            except Exception:
                current_app.logger.exception('Could not record security audit event.')
        return response

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
