from flask import Blueprint, jsonify, request, current_app
from models import find_ups_by_id, generate_ups_id
from utils.ups import test_ups_connection, get_ups_data
from utils.network import is_valid_ip
from services.uptime import get_uptime_statistics, get_event_timeline
from config import RATE_LIMITS
import logging
import re

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api')

def get_state_manager():
    return current_app.state_manager

@api_bp.route('/ups', methods=['POST'])
def api_add_ups():
    current_app.limiter.limit(RATE_LIMITS['api_write'])(lambda: None)()
    
    state_manager = get_state_manager()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        
        name = data.get('name', '').strip()
        ip = data.get('ip', '').strip()
        port = data.get('port', 3493)
        
        if not name:
            return jsonify({'success': False, 'message': 'UPS name is required'}), 400
        if not is_valid_ip(ip):
            return jsonify({'success': False, 'message': 'Invalid IP address'}), 400
        if not isinstance(port, int) or not (1 <= port <= 65535):
            return jsonify({'success': False, 'message': 'Port must be between 1 and 65535'}), 400
        
        settings = state_manager.get('settings', {})
        existing_names = [u['name'].lower() for u in settings.get('ups_configs', [])]
        if name.lower() in existing_names:
            return jsonify({'success': False, 'message': f'UPS name "{name}" already exists'}), 400
        
        new_ups = {
            'id': generate_ups_id(name, ip),
            'name': name,
            'ip': ip,
            'port': port
        }
        
        settings['ups_configs'].append(new_ups)
        state_manager.save()
        state_manager.add_log(f"Added UPS: {name}", 'INFO')
        
        return jsonify({'success': True, 'message': f'UPS {name} added successfully', 'ups': new_ups}), 201
        
    except Exception as e:
        logger.error(f"Error adding UPS: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@api_bp.route('/ups/<ups_id>', methods=['PUT'])
def api_update_ups(ups_id):
    current_app.limiter.limit(RATE_LIMITS['device_action'])(lambda: None)()
    
    state_manager = get_state_manager()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        
        index, ups = find_ups_by_id(state_manager.state, ups_id)
        if ups is None:
            return jsonify({'success': False, 'message': 'UPS not found'}), 404
        
        name = data.get('name', '').strip()
        ip = data.get('ip', '').strip()
        port = data.get('port', 3493)
        
        if not name:
            return jsonify({'success': False, 'message': 'UPS name is required'}), 400
        if not is_valid_ip(ip):
            return jsonify({'success': False, 'message': 'Invalid IP address'}), 400
        if not isinstance(port, int) or not (1 <= port <= 65535):
            return jsonify({'success': False, 'message': 'Port must be between 1 and 65535'}), 400
        
        settings = state_manager.get('settings', {})
        for i, u in enumerate(settings['ups_configs']):
            if i != index and u['name'].lower() == name.lower():
                return jsonify({'success': False, 'message': f'UPS name "{name}" already exists'}), 400
        
        settings['ups_configs'][index].update({
            'name': name,
            'ip': ip,
            'port': port
        })
        
        state_manager.save()
        state_manager.add_log(f"Updated UPS: {name}", 'INFO')
        
        return jsonify({'success': True, 'message': f'UPS {name} updated successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error updating UPS {ups_id}: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@api_bp.route('/ups/<ups_id>', methods=['DELETE'])
def api_delete_ups(ups_id):
    current_app.limiter.limit(RATE_LIMITS['device_action'])(lambda: None)()
    
    state_manager = get_state_manager()
    
    try:
        index, ups = find_ups_by_id(state_manager.state, ups_id)
        if ups is None:
            return jsonify({'success': False, 'message': 'UPS not found'}), 404
        
        ups_name = ups['name']
        settings = state_manager.get('settings', {})
        settings['ups_configs'].pop(index)
        
        state_manager.save()
        state_manager.add_log(f"Removed UPS: {ups_name}", 'INFO')
        
        return jsonify({'success': True, 'message': f'UPS {ups_name} removed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error deleting UPS {ups_id}: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@api_bp.route('/ups/test', methods=['POST'])
def api_test_ups():
    current_app.limiter.limit(RATE_LIMITS['device_action'])(lambda: None)()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        
        ups_config = {
            'name': data.get('name', ''),
            'ip': data.get('ip', ''),
            'port': data.get('port', 3493)
        }
        
        success, message = test_ups_connection(ups_config)
        return jsonify({'success': success, 'message': message}), 200
        
    except Exception as e:
        logger.error(f"Error testing UPS connection: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@api_bp.route('/settings', methods=['PUT'])
def api_update_settings():
    current_app.limiter.limit(RATE_LIMITS['api_write'])(lambda: None)()
    
    state_manager = get_state_manager()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        
        try:
            refresh_interval = int(data.get('refresh_interval', 30))
            log_retention = int(data.get('log_retention', 100))
            discovery_timeout = int(data.get('discovery_timeout', 2))
            wol_battery_threshold = int(data.get('wol_battery_threshold', 80))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid numeric values in settings'}), 400
        
        ip_scan_range = data.get('ip_scan_range', '192.168.1.0/24').strip()
        if not re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-9]|[1-2][0-9]|3[0-2]))?$', ip_scan_range):
            return jsonify({'success': False, 'message': 'Invalid IP scan range format'}), 400
        
        verbose_logging = data.get('verbose_logging', 'false')
        if isinstance(verbose_logging, str):
            verbose_logging = verbose_logging.lower() == 'true'
        
        theme = data.get('theme', 'dark')
        if theme not in ['dark', 'light']:
            theme = 'dark'
        
        settings = state_manager.get('settings', {})
        settings.update({
            'refresh_interval': refresh_interval,
            'log_retention': log_retention,
            'ip_scan_range': ip_scan_range,
            'discovery_timeout': discovery_timeout,
            'wol_battery_threshold': wol_battery_threshold,
            'verbose_logging': verbose_logging,
            'theme': theme
        })
        
        state_manager.save()
        state_manager.add_log("General settings updated", 'INFO')
        
        return jsonify({'success': True, 'message': 'Settings updated successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@api_bp.route('/ups/status')
def get_ups_status():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    ups_configs = settings.get('ups_configs', [])
    ups_data = get_ups_data(ups_configs, state_manager)
    return jsonify(ups_systems=ups_data)

@api_bp.route('/uptime/stats')
def get_uptime_stats():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    stats = get_uptime_statistics(state_manager)
    return jsonify(stats=stats)

@api_bp.route('/events/timeline')
def get_events():
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    events = get_event_timeline(state_manager)
    return jsonify(events=events)

@api_bp.route('/theme/toggle', methods=['POST'])
def toggle_theme():
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    
    current_theme = settings.get('theme', 'dark')
    new_theme = 'light' if current_theme == 'dark' else 'dark'
    
    settings['theme'] = new_theme
    state_manager.save()
    
    return jsonify({'success': True, 'theme': new_theme})