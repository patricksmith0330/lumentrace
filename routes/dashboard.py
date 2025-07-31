from flask import Blueprint, render_template, jsonify, current_app
from utils.ups import get_ups_data
from services.uptime import get_uptime_statistics, get_event_timeline
from config import RATE_LIMITS, DEFAULT_SETTINGS

dashboard_bp = Blueprint('dashboard', __name__)

def get_state_manager():
    return current_app.state_manager

@dashboard_bp.route('/')
def dashboard():
    state_manager = get_state_manager()
    settings = state_manager.get('settings', DEFAULT_SETTINGS)
    return render_template('dashboard.html', settings=settings)

@dashboard_bp.route('/get_ups_status')
def get_ups_status():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    ups_configs = settings.get('ups_configs', [])
    ups_data = get_ups_data(ups_configs, state_manager)
    return jsonify(ups_systems=ups_data)

@dashboard_bp.route('/get_battery_analytics')
def get_battery_analytics():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    history = state_manager.get('battery_history', [])
    predicted_time = 'Insufficient data'
    
    if len(history) >= 2:
        from utils.analytics import predict_battery_time
        predicted_time = predict_battery_time(history)
    
    return jsonify(history=history, predicted_time=predicted_time)

@dashboard_bp.route('/get_devices')
def get_devices():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    devices = state_manager.get('devices', [])
    return jsonify(devices=devices)

@dashboard_bp.route('/get_logs')
def get_logs():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    logs = state_manager.get('logs', [])
    return jsonify(logs=logs)

@dashboard_bp.route('/get_uptime_stats')
def get_uptime_stats():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    stats = get_uptime_statistics(state_manager)
    return jsonify(stats=stats)

@dashboard_bp.route('/get_event_timeline')
def get_event_timeline():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    events = get_event_timeline(state_manager)
    return jsonify(events=events)