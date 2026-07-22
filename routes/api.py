import logging

from flask import Blueprint, current_app, jsonify, request

from config import RATE_LIMITS
from extensions import limiter
from models import find_ups_by_id, generate_ups_id
from utils.network import is_valid_ip
from utils.ups import get_ups_data, test_ups_connection


logger = logging.getLogger(__name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.get('/health')
@limiter.exempt
def health():
    return jsonify(status='ok')


def _ups_payload(data):
    name = str(data.get('name', '')).strip()
    ip = str(data.get('ip', '')).strip()
    try:
        port = int(data.get('port', 3493))
    except (TypeError, ValueError):
        return None, 'Port must be a number.'
    if not name or len(name) > 80:
        return None, 'Enter a UPS name between 1 and 80 characters.'
    if not is_valid_ip(ip):
        return None, 'Enter a valid IP address.'
    if not 1 <= port <= 65535:
        return None, 'Port must be between 1 and 65535.'
    return {'name': name, 'ip': ip, 'port': port}, None


@api_bp.post('/ups')
@limiter.limit(RATE_LIMITS['api_write'])
def add_ups():
    payload, error = _ups_payload(request.get_json(silent=True) or {})
    if error:
        return jsonify(success=False, message=error), 400

    manager = current_app.state_manager
    with manager.locked() as state:
        configs = state['settings']['ups_configs']
        if any(item['name'].lower() == payload['name'].lower() for item in configs):
            return jsonify(success=False, message='A UPS with that name already exists.'), 409
        payload['id'] = generate_ups_id(payload['name'], payload['ip'])
        configs.append(payload)
        manager.save()
    manager.add_log(f"Added UPS: {payload['name']}", 'INFO')
    return jsonify(success=True, message='UPS added.', ups=payload), 201


@api_bp.put('/ups/<ups_id>')
@limiter.limit(RATE_LIMITS['api_write'])
def update_ups(ups_id):
    payload, error = _ups_payload(request.get_json(silent=True) or {})
    if error:
        return jsonify(success=False, message=error), 400

    manager = current_app.state_manager
    with manager.locked() as state:
        index, ups = find_ups_by_id(state, ups_id)
        if ups is None:
            return jsonify(success=False, message='UPS not found.'), 404
        configs = state['settings']['ups_configs']
        if any(i != index and item['name'].lower() == payload['name'].lower() for i, item in enumerate(configs)):
            return jsonify(success=False, message='A UPS with that name already exists.'), 409
        configs[index].update(payload)
        manager.save()
    manager.add_log(f"Updated UPS: {payload['name']}", 'INFO')
    return jsonify(success=True, message='UPS updated.')


@api_bp.delete('/ups/<ups_id>')
@limiter.limit(RATE_LIMITS['device_action'])
def delete_ups(ups_id):
    manager = current_app.state_manager
    with manager.locked() as state:
        index, ups = find_ups_by_id(state, ups_id)
        if ups is None:
            return jsonify(success=False, message='UPS not found.'), 404
        removed = state['settings']['ups_configs'].pop(index)
        manager.save()
    manager.add_log(f"Removed UPS: {removed['name']}", 'INFO')
    return jsonify(success=True, message='UPS removed.')


@api_bp.post('/ups/test')
@limiter.limit(RATE_LIMITS['device_action'])
def test_ups():
    payload, error = _ups_payload(request.get_json(silent=True) or {})
    if error:
        return jsonify(success=False, message=error), 400
    success, message = test_ups_connection(payload)
    return jsonify(success=success, message=message), 200 if success else 422


@api_bp.get('/ups/status')
@limiter.limit(RATE_LIMITS['api_read'])
def ups_status():
    manager = current_app.state_manager
    configs = manager.get('settings', {}).get('ups_configs', [])
    return jsonify(ups_systems=get_ups_data(configs, manager))
