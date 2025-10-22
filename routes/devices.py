from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from utils.network import is_valid_mac, is_valid_ip, get_mac_from_ip, send_wol, discover_devices, is_device_online
from config import RATE_LIMITS

devices_bp = Blueprint('devices', __name__)

def get_state_manager():
    return current_app.state_manager

@devices_bp.route('/wake_device', methods=['POST'])
def wake_device_route():
    current_app.limiter.limit(RATE_LIMITS['device_action'])(lambda: None)()
    
    state_manager = get_state_manager()
    mac = request.get_json().get('mac')
    if not mac: 
        return jsonify(success=False, message="MAC is required."), 400
    if send_wol(mac, state_manager):
        return jsonify(success=True, message=f"WOL packet sent to {mac}.")
    return jsonify(success=False, message="WOL failed.")

@devices_bp.route('/add_device', methods=['GET', 'POST'])
def add_device():
    current_app.limiter.limit(RATE_LIMITS['api_write'])(lambda: None)()
    
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        mac = request.form.get('mac', '').strip().upper()
        ip = request.form['ip'].strip()
        devices = state_manager.get('devices', [])
        existing_ips = {dev['ip'] for dev in devices}
        existing_macs = {dev['mac'] for dev in devices if dev.get('mac')}

        if mac and not is_valid_mac(mac):
            flash('Error: Invalid MAC address format.', 'error')
            return render_template('add_device.html', settings=settings, prefill_ip=ip, prefill_mac=mac)
        if not is_valid_ip(ip):
            flash('Error: Invalid IP address format.', 'error')
            return render_template('add_device.html', settings=settings, prefill_ip=ip, prefill_mac=mac)

        if ip in existing_ips:
            flash(f'Error: A device with the IP address {ip} already exists.', 'error')
            return render_template('add_device.html', settings=settings, prefill_ip=ip, prefill_mac=mac)
        if mac and mac in existing_macs:
            flash(f'Error: A device with the MAC address {mac} already exists.', 'error')
            return render_template('add_device.html', settings=settings, prefill_ip=ip, prefill_mac=mac)

        if not mac:
            detected_mac = get_mac_from_ip(ip)
            if detected_mac:
                mac = detected_mac
                state_manager.add_log(f"Auto-detected MAC for {ip}: {mac}", 'INFO')
            else:
                state_manager.add_log(f"Could not auto-detect MAC for {ip}. Please enter it manually if needed for WOL.", 'WARNING')
                flash(f'Warning: Could not auto-detect MAC for {ip}. Device will be added without it.', 'warning')

        devices.append({'name': name, 'mac': mac, 'ip': ip, 'online': False, 'last_seen': None})
        state_manager.save()
        flash(f'Successfully added device: {name}', 'success')
        return redirect(url_for('dashboard.dashboard'))

    prefill_ip = request.args.get('ip', '')
    prefill_mac = request.args.get('mac', '')
    return render_template('add_device.html', settings=settings, prefill_ip=prefill_ip, prefill_mac=prefill_mac)

@devices_bp.route('/add_selected_devices', methods=['POST'])
def add_selected_devices():
    current_app.limiter.limit(RATE_LIMITS['discovery'])(lambda: None)()
    
    state_manager = get_state_manager()
    selected_devices = request.get_json()
    added_count, skipped_count = 0, 0
    devices = state_manager.get('devices', [])
    existing_ips = {dev['ip'] for dev in devices}
    existing_macs = {dev['mac'] for dev in devices if dev.get('mac')}
    
    for dev_info in selected_devices:
        ip = dev_info.get('ip')
        mac = dev_info.get('mac', '').strip().upper()
        if not ip or ip in existing_ips or (mac and mac in existing_macs):
            skipped_count += 1
            continue

        if mac and not is_valid_mac(mac):
            skipped_count += 1
            continue
        if not is_valid_ip(ip):
            skipped_count += 1
            continue

        name = dev_info.get('name') or f"Device-{ip.replace('.', '-')}"
        devices.append({'name': name, 'mac': mac, 'ip': ip, 'online': False, 'last_seen': None})
        added_count += 1
        
    state_manager.save()
    message = f"Added {added_count} device(s). Skipped {skipped_count}."
    flash(message, 'success' if added_count > 0 else 'warning')
    return jsonify(success=True, message=message)

@devices_bp.route('/remove_device', methods=['POST'])
def remove_device():
    current_app.limiter.limit(RATE_LIMITS['device_action'])(lambda: None)()
    
    state_manager = get_state_manager()
    data = request.get_json()
    index = data.get('index')
    devices = state_manager.get('devices', [])
    
    if index is None or not (0 <= index < len(devices)):
        return jsonify(success=False, message="Device not found."), 404
        
    dev = devices.pop(index)
    state_manager.save()
    state_manager.add_log(f'Removed device: {dev["name"]}', 'INFO')
    return jsonify(success=True, message=f'Device {dev["name"]} removed.')

@devices_bp.route('/discover')
def discover():
    current_app.limiter.limit(RATE_LIMITS['discovery'])(lambda: None)()
    
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    ip_range = settings.get('ip_scan_range', '192.168.1.0/24')
    timeout = settings.get('discovery_timeout', 2)
    
    found_devices = discover_devices(ip_range, timeout, state_manager)
    added_ips = {dev['ip'] for dev in state_manager.get('devices', [])}
    new_devices = [dev for dev in found_devices if dev['ip'] not in added_ips and dev.get('mac')]
    
    return render_template('discover.html', settings=settings, devices=new_devices)

@devices_bp.route('/device/<ip_address>')
def device_detail(ip_address):
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    devices = state_manager.get('devices', [])
    
    device = None
    device_index = -1
    for i, dev in enumerate(devices):
        if dev['ip'] == ip_address:
            device = dev
            device_index = i
            break

    if not device:
        flash(f'Error: Device with IP {ip_address} not found.', 'error')
        return redirect(url_for('dashboard.dashboard'))

    current_online_status = is_device_online(device['ip'], state_manager)

    return render_template(
        'device_detail.html',
        settings=settings,
        device=device,
        current_online=current_online_status,
        index=device_index
    )

@devices_bp.route('/edit_device/<int:index>', methods=['GET', 'POST'])
def edit_device(index):
    current_app.limiter.limit(RATE_LIMITS['api_write'])(lambda: None)()
    
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    devices = state_manager.get('devices', [])
    
    if not (0 <= index < len(devices)):
        return redirect(url_for('dashboard.dashboard'))
    
    device_to_edit = devices[index]

    if request.method == 'POST':
        name = request.form['name'].strip()
        mac = request.form.get('mac', '').strip().upper()
        ip = request.form['ip'].strip()

        if mac and not is_valid_mac(mac):
            flash('Error: Invalid MAC address format.', 'error')
            return render_template('edit_device.html', settings=settings, device=device_to_edit, index=index)
        if not is_valid_ip(ip):
            flash('Error: Invalid IP address format.', 'error')
            return render_template('edit_device.html', settings=settings, device=device_to_edit, index=index)

        if any(d['ip'] == ip and i != index for i, d in enumerate(devices)):
            flash(f'Error: IP {ip} already exists.', 'error')
            return render_template('edit_device.html', settings=settings, device=device_to_edit, index=index)
        
        devices[index].update({'name': name, 'mac': mac, 'ip': ip})
        state_manager.save()
        flash(f'Updated device: {name}', 'success')
        return redirect(url_for('dashboard.dashboard'))
    
    return render_template('edit_device.html', settings=settings, device=device_to_edit, index=index)

@devices_bp.route('/device_status/<ip>')
def device_status(ip):
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    devices = state_manager.get('devices', [])
    
    try:
        device = next((d for d in devices if d.get('ip') == ip), None)
        
        if not device:
            return jsonify({'online': False, 'last_seen': None})
        
        is_online = is_device_online(ip, state_manager)
        
        if is_online:
            device['online'] = True
            state_manager.save()
            last_seen = device.get('last_seen')
        else:
            device['online'] = False
            last_seen = device.get('last_seen', None)
        
        return jsonify({
            'online': is_online,
            'last_seen': last_seen
        })
        
    except Exception as e:
        return jsonify({'online': False, 'last_seen': None, 'error': str(e)})

@devices_bp.route('/discover_mac')
def discover_mac():
    """Discover MAC address for an IP"""
    current_app.limiter.limit(RATE_LIMITS['api_read'])(lambda: None)()
    
    state_manager = get_state_manager()
    ip = request.args.get('ip')
    
    if not ip:
        return jsonify({'success': False, 'message': 'IP address required'})
    
    if not is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'Invalid IP address'})
    
    try:
        mac = get_mac_from_ip(ip)
        
        if mac:
            state_manager.add_log(f"Discovered MAC for {ip}: {mac}", 'INFO')
            return jsonify({
                'success': True,
                'mac': mac,
                'message': 'MAC address discovered'
            })
        else:
            return jsonify({
                'success': False,
                'mac': None,
                'message': 'Could not discover MAC address'
            })
    except Exception as e:
        current_app.logger.error(f"MAC discovery error for {ip}: {e}")
        return jsonify({
            'success': False,
            'mac': None,
            'message': f'Error discovering MAC: {str(e)}'
        })
    
@devices_bp.route('/update_device_order', methods=['POST'])
def update_device_order():
    """Receives the new order of devices and saves it to the state."""
    try:
        new_ordered_ips = request.get_json()
        if not isinstance(new_ordered_ips, list):
            return jsonify({"status": "error", "message": "Invalid data format."}), 400

        state = current_app.state_manager.get_state()
        devices_by_ip = {device['ip']: device for device in state['devices']}
        new_device_list = [devices_by_ip[ip] for ip in new_ordered_ips if ip in devices_by_ip]

        if len(new_device_list) != len(state['devices']):
            return jsonify({"status": "error", "message": "Device list mismatch."}), 400

        state['devices'] = new_device_list
        current_app.state_manager.save_state(state)
        return jsonify({"status": "success", "message": "Device order updated."})
    except Exception as e:
        current_app.logger.error(f"Error updating device order: {e}")
        return jsonify({"status": "error", "message": "Internal server error."}), 500