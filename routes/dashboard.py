from flask import Blueprint, current_app, jsonify, render_template

from config import DEFAULT_SETTINGS, RATE_LIMITS
from extensions import limiter
from utils.analytics import predict_battery_time
from utils.ups import get_ups_data


dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.get('/')
def dashboard():
    settings = current_app.state_manager.get('settings', DEFAULT_SETTINGS)
    return render_template('dashboard.html', settings=settings)


@dashboard_bp.get('/api/dashboard')
@limiter.limit(RATE_LIMITS['api_read'])
def dashboard_data():
    snapshot = current_app.state_manager.snapshot()
    settings = snapshot.get('settings', {})
    history = snapshot.get('battery_history', [])
    predicted_time = predict_battery_time(history) if len(history) >= 2 else 'Insufficient data'

    return jsonify(
        ups_systems=get_ups_data(settings.get('ups_configs', []), current_app.state_manager),
        devices=snapshot.get('devices', []),
        logs=snapshot.get('logs', [])[-30:][::-1],
        recovery_state=snapshot.get('recovery_state', 'NORMAL'),
        predicted_time=predicted_time,
        battery_history=history,
    )
