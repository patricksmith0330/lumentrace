from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for

from config import RATE_LIMITS
from extensions import limiter
from routes.auth import admin_required
from utils.network import (
    discover_devices,
    get_mac_from_ip,
    is_device_online,
    is_valid_ip,
    is_valid_mac,
    send_wol,
)


devices_bp = Blueprint('devices', __name__)


def _validated_device(form, devices, current_index=None):
    name = form.get('name', '').strip()
    ip = form.get('ip', '').strip()
    mac = form.get('mac', '').strip().upper().replace('-', ':')

    if not name or len(name) > 80:
        return None, 'Enter a device name between 1 and 80 characters.'
    if not is_valid_ip(ip):
        return None, 'Enter a valid IP address.'
    if mac and not is_valid_mac(mac):
        return None, 'Enter a valid MAC address such as AA:BB:CC:DD:EE:FF.'

    for index, device in enumerate(devices):
        if index == current_index:
            continue
        if device.get('ip') == ip:
            return None, f'A device with IP address {ip} already exists.'
        if mac and device.get('mac') == mac:
            return None, f'A device with MAC address {mac} already exists.'

    return {'name': name, 'ip': ip, 'mac': mac}, None


@devices_bp.post('/wake_device')
@limiter.limit(RATE_LIMITS['device_action'])
def wake_device_route():
    data = request.get_json(silent=True) or {}
    mac = data.get('mac', '').strip().upper().replace('-', ':')
    if not is_valid_mac(mac):
        return jsonify(success=False, message='A valid MAC address is required.'), 400
    if send_wol(mac, current_app.state_manager):
        return jsonify(success=True, message='Wake packet sent.')
    return jsonify(success=False, message='The wake packet could not be sent.'), 500


@devices_bp.route('/add_device', methods=['GET', 'POST'])
@limiter.limit(RATE_LIMITS['api_write'], methods=['POST'])
@admin_required
def add_device():
    manager = current_app.state_manager
    settings = manager.get('settings', {})
    initial = {
        'name': request.form.get('name', ''),
        'ip': request.form.get('ip', request.args.get('ip', '')),
        'mac': request.form.get('mac', request.args.get('mac', '')),
    }

    if request.method == 'POST':
        with manager.locked() as state:
            device, error = _validated_device(request.form, state.get('devices', []))
            if error:
                flash(error, 'error')
                return render_template('add_device.html', settings=settings, initial=initial)

            if not device['mac']:
                device['mac'] = get_mac_from_ip(device['ip']) or ''
                if not device['mac']:
                    flash('Device added without a MAC address. Wake-on-LAN will be unavailable.', 'warning')

            device.update(online=False, last_seen=None)
            state['devices'].append(device)
            manager.save()
        manager.add_log(f"Added device: {device['name']}", 'INFO')
        flash(f"Added {device['name']}.", 'success')
        return redirect(url_for('dashboard.dashboard'))

    return render_template('add_device.html', settings=settings, initial=initial)


@devices_bp.route('/edit_device/<int:index>', methods=['GET', 'POST'])
@limiter.limit(RATE_LIMITS['api_write'], methods=['POST'])
@admin_required
def edit_device(index):
    manager = current_app.state_manager
    settings = manager.get('settings', {})
    devices = manager.get('devices', [])
    if not 0 <= index < len(devices):
        flash('Device not found.', 'error')
        return redirect(url_for('dashboard.dashboard'))

    if request.method == 'POST':
        with manager.locked() as state:
            device, error = _validated_device(request.form, state['devices'], current_index=index)
            if error:
                flash(error, 'error')
                initial = dict(state['devices'][index], **request.form.to_dict())
                return render_template('edit_device.html', settings=settings, initial=initial, index=index)
            state['devices'][index].update(device)
            manager.save()
        manager.add_log(f"Updated device: {device['name']}", 'INFO')
        flash(f"Updated {device['name']}.", 'success')
        return redirect(url_for('dashboard.dashboard'))

    return render_template('edit_device.html', settings=settings, initial=devices[index], index=index)


@devices_bp.post('/remove_device')
@limiter.limit(RATE_LIMITS['device_action'])
def remove_device():
    data = request.get_json(silent=True) or {}
    index = data.get('index')
    manager = current_app.state_manager
    with manager.locked() as state:
        devices = state.get('devices', [])
        if not isinstance(index, int) or not 0 <= index < len(devices):
            return jsonify(success=False, message='Device not found.'), 404
        removed = devices.pop(index)
        state.get('uptime_stats', {}).pop(removed.get('ip'), None)
        manager.save()
    manager.add_log(f"Removed device: {removed['name']}", 'INFO')
    return jsonify(success=True, message=f"Removed {removed['name']}.")


@devices_bp.get('/discover')
@admin_required
def discover():
    return render_template('discover.html', settings=current_app.state_manager.get('settings', {}))


@devices_bp.post('/discover/scan')
@limiter.limit(RATE_LIMITS['discovery'])
def scan_network():
    manager = current_app.state_manager
    settings = manager.get('settings', {})
    found = discover_devices(
        settings.get('ip_scan_range', '192.168.1.0/24'),
        settings.get('discovery_timeout', 2),
        manager,
    )
    existing_ips = {device['ip'] for device in manager.get('devices', [])}
    devices = [device for device in found if device.get('ip') not in existing_ips and device.get('mac')]
    return jsonify(success=True, devices=devices)


@devices_bp.post('/add_selected_devices')
@limiter.limit(RATE_LIMITS['discovery'])
def add_selected_devices():
    selected = request.get_json(silent=True)
    if not isinstance(selected, list):
        return jsonify(success=False, message='Select at least one device.'), 400

    manager = current_app.state_manager
    added = 0
    skipped = 0
    with manager.locked() as state:
        devices = state.get('devices', [])
        for item in selected:
            candidate = {
                'name': item.get('name') or f"Device {item.get('ip', '')}",
                'ip': item.get('ip', ''),
                'mac': item.get('mac', ''),
            }
            device, error = _validated_device(candidate, devices)
            if error:
                skipped += 1
                continue
            device.update(online=False, last_seen=None)
            devices.append(device)
            added += 1
        manager.save()

    manager.add_log(f'Network discovery added {added} device(s).', 'INFO')
    return jsonify(success=True, message=f'Added {added} device(s); skipped {skipped}.')


@devices_bp.get('/device_status/<ip>')
@limiter.limit(RATE_LIMITS['api_read'])
def device_status(ip):
    if not is_valid_ip(ip):
        return jsonify(online=False, last_seen=None), 400
    manager = current_app.state_manager
    device = next((item for item in manager.get('devices', []) if item.get('ip') == ip), None)
    if not device:
        return jsonify(online=False, last_seen=None), 404
    online = is_device_online(ip, manager)
    with manager.locked():
        device['online'] = online
        manager.save()
    return jsonify(online=online, last_seen=device.get('last_seen'))


@devices_bp.get('/discover_mac')
@limiter.limit(RATE_LIMITS['api_read'])
def discover_mac():
    ip = request.args.get('ip', '')
    if not is_valid_ip(ip):
        return jsonify(success=False, message='Enter a valid IP address.'), 400
    mac = get_mac_from_ip(ip)
    if not mac:
        return jsonify(success=False, message='No MAC address was found.'), 404
    return jsonify(success=True, mac=mac, message='MAC address found.')
