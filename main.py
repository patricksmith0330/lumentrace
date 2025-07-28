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
import json
import subprocess
import socket
import logging
import threading
import time
from datetime import datetime
from collections import defaultdict
import ipaddress
import sys

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path

from pythonjsonlogger import jsonlogger
from waitress import serve

def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac) is not None

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

logHandler = logging.StreamHandler(sys.stdout)

formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s'
)
logHandler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(logHandler)

app = Flask(__name__)

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=REDIS_URL
)
limiter.init_app(app)

app.secret_key = os.getenv('SECRET_KEY', 'dev_secret_fallback')

app.config['TEMPLATES_AUTO_RELOAD'] = True

for handler in list(app.logger.handlers):
    app.logger.removeHandler(handler)

app.logger.addHandler(logHandler)
app.logger.setLevel(logging.INFO)


from scipy.stats import linregress
from ping3 import ping
from filelock import FileLock
from scapy.all import srp, Ether, ARP, getmacbyip


POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 10))
DATA_DIR = os.environ.get('DATA_DIR', '/data')
DATA_FILE = os.path.join(DATA_DIR, 'state.json')
DATA_LOCK_FILE = os.path.join(DATA_DIR, 'state.lock')

DEFAULT_SETTINGS = {
    'refresh_interval': 30,
    'log_retention': 100,
    'ip_scan_range': '192.168.1.0/24',
    'discovery_timeout': 2,
    'ups_configs': [
        {'name': 'ups', 'ip': 'localhost', 'port': 3493}
    ],
    'density': 'comfortable',
    'wol_battery_threshold': 80,
    'verbose_logging': False
}

DEFAULT_STATE = {
    'devices': [],
    'settings': DEFAULT_SETTINGS,
    'last_status': '',
    'outage_snapshot': [],
    'logs': [],
    'battery_history': []
}

state = DEFAULT_STATE.copy()

ups_cache = defaultdict(lambda: {'data': None, 'timestamp': 0})
CACHE_TTL = 5

def load_state():
    global state
    lock = FileLock(DATA_LOCK_FILE, timeout=10)
    with lock:
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, 'r') as f:
                    loaded_state = json.load(f)
                    state = {**DEFAULT_STATE, **loaded_state}
                    state['settings'] = {**DEFAULT_SETTINGS, **state.get('settings', {})}
                    for device in state.get('devices', []):
                        device.setdefault('last_seen', None)
                logger.info(f"Loaded state from {DATA_FILE}")
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Error loading state from {DATA_FILE}: {e}. Initializing with default state.")
                state = DEFAULT_STATE.copy()
                save_state_unlocked()
        else:
            logger.info(f"No state file, initializing with default state.")
            state = DEFAULT_STATE.copy()
            save_state_unlocked()

def save_state_unlocked():
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, 'w') as f:
            json.dump(state, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving state to {DATA_FILE}: {e}")

def save_state():
    with FileLock(DATA_LOCK_FILE, timeout=10):
        save_state_unlocked()

def add_log(message, level='INFO'):
    current_time = datetime.now().isoformat(timespec='seconds')
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(message, extra={'log_type': 'app_event', 'event': message})
    state['logs'].append({'time': current_time, 'message': message, 'level': level})
    max_logs = state.get('settings', {}).get('log_retention', 100)
    state['logs'] = state['logs'][-max_logs:]
    save_state()

def get_ups_data():
    all_ups_data = []
    for config in state.get('settings', {}).get('ups_configs', []):
        ups_name, host, port = config.get('name'), config.get('ip'), config.get('port', 3493)
        cache_key = f"{host}:{port}:{ups_name}"
        if ups_cache[cache_key]['data'] and (time.time() - ups_cache[cache_key]['timestamp']) < CACHE_TTL:
            all_ups_data.append(ups_cache[cache_key]['data'])
            continue
        try:
            cmd = ['upsc', f'{ups_name}@{host}:{port}']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if process.returncode != 0:
                error_message = process.stderr.strip() if process.stderr else f"Command returned non-zero exit status {process.returncode}."
                raise RuntimeError(f"upsc failed: {error_message}")

            output = process.stdout
            data_map = {line.split(': ', 1)[0]: line.split(': ', 1)[1] for line in output.splitlines() if ': ' in line}
            status = data_map.get('ups.status', 'UNKNOWN').split()[0]
            data = {'name': ups_name, 'status': status, 'battery': int(float(data_map.get('battery.charge', 0))), 'input_voltage': float(data_map.get('input.voltage', 0)), 'output_voltage': float(data_map.get('output.voltage', 0)), 'load': float(data_map.get('ups.load', 0))}
            ups_cache[cache_key] = {'data': data, 'timestamp': time.time()}
            all_ups_data.append(data)
        except subprocess.TimeoutExpired:
            add_log(f'UPS query for {ups_name}@{host} timed out.', 'WARNING')
            all_ups_data.append({'name': ups_name, 'status': 'TIMEOUT', 'battery': 0, 'input_voltage': 0, 'output_voltage': 0, 'load': 0})
        except Exception as e:
            add_log(f'UPS query failed for {ups_name}@{host}: {e}', 'ERROR')
            all_ups_data.append({'name': ups_name, 'status': 'ERROR', 'battery': 0, 'input_voltage': 0, 'output_voltage': 0, 'load': 0})
    return all_ups_data

def is_device_online(ip):
    try:
        if ping(ip, timeout=0.8) is not None:
            for dev in state['devices']:
                if dev['ip'] == ip:
                    dev['last_seen'] = time.time()
                    break
            return True
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {e}")
    return False

def send_wol(mac):
    try:
        mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
        packet = b'\xff' * 6 + mac_bytes * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, ('<broadcast>', 9))
        add_log(f"WOL packet sent to MAC: {mac}", 'INFO')
        return True
    except Exception as e:
        add_log(f'WOL failed for MAC {mac}: {e}', 'ERROR')
        return False

def get_mac_from_ip(ip):
    try:
        ping(ip, timeout=0.5)
        time.sleep(0.5)
        mac = getmacbyip(ip)
        if mac: return mac.upper()
    except Exception as e:
        logger.warning(f"Scapy's getmacbyip failed for {ip}: {e}")
    return None

def discover_devices():
    ip_range = state.get('settings', {}).get('ip_scan_range', '192.168.1.0/24')
    timeout = state.get('settings', {}).get('discovery_timeout', 2)
    logger.info(f"Scanning network: {ip_range}")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=timeout, verbose=0)
        return [{'ip': r.psrc, 'mac': r.hwsrc.upper()} for s, r in ans]
    except Exception as e:
        add_log(f"Scapy ARP scan failed for range {ip_range}: {e}. Ensure NET_RAW and NET_BROADCAST capabilities are granted.", 'ERROR')
        return []

def monitor_loop():
    load_state()
    while True:
        try:
            if state.get('settings', {}).get('verbose_logging', False):
                add_log("Polling UPS and device status...", 'DEBUG')
            
            threshold = state.get('settings', {}).get('wol_battery_threshold', 80)
            all_ups = get_ups_data()
            if all_ups:
                is_on_battery = any(u.get('status') == 'OB' for u in all_ups)
                is_online = all(u.get('status') == 'OL' for u in all_ups)
                overall_status = 'OB' if is_on_battery else 'OL' if is_online else 'MIXED'
                if is_on_battery:
                    on_battery_ups = [u['battery'] for u in all_ups if u.get('status') == 'OB']
                    if on_battery_ups:
                        state['battery_history'].append({'timestamp': time.time(), 'battery': min(on_battery_ups)})
                        state['battery_history'] = state['battery_history'][-state['settings']['log_retention']:]
                if state['last_status'] != 'OB' and overall_status == 'OB':
                    add_log('Outage detected. Taking snapshot of online devices.', 'WARNING')
                    state['outage_snapshot'] = [d['mac'] for d in state['devices'] if d.get('mac') and is_device_online(d['ip'])]
                elif state['last_status'] == 'OB' and overall_status == 'OL':
                    add_log('Power restored. Checking battery before WOL.', 'INFO')
                    if all(u.get('battery', 0) >= threshold for u in all_ups) and state['outage_snapshot']:
                        add_log(f'UPS units charged past {threshold}%. Sending WOL.', 'INFO')
                        for mac in state['outage_snapshot']:
                            send_wol(mac)
                        state['outage_snapshot'] = []
                state['last_status'] = overall_status
            for dev in state['devices']:
                dev['online'] = is_device_online(dev['ip'])
            save_state()
        except Exception as e:
            logger.error(f"Error in monitor loop: {e}")
        time.sleep(POLL_INTERVAL)

@app.route('/')
def dashboard():
    return render_template('dashboard.html', settings=state.get('settings', DEFAULT_SETTINGS))

@app.route('/get_ups_status')
@limiter.limit("60 per minute")
def get_ups_status():
    return jsonify(ups_systems=get_ups_data())

@app.route('/get_battery_analytics')
@limiter.limit("60 per minute")
def get_battery_analytics():
    history = state['battery_history']
    predicted_time = 'Insufficient data'
    if len(history) >= 2:
        timestamps = [h['timestamp'] for h in history]
        batteries = [h['battery'] for h in history]
        try:
            slope, intercept, _, _, _ = linregress(timestamps, batteries)
            if slope >= -0.001:
                predicted_time = 'Charging or stable'
            else:
                time_to_zero = (0 - intercept) / slope
                time_rem = time_to_zero - time.time()
                if time_rem > 0:
                    hours, rem = divmod(time_rem, 3600)
                    minutes, _ = divmod(rem, 60)
                    predicted_time = f'{int(hours)}h {int(minutes)}m remaining'
                else:
                    predicted_time = 'Very low'
        except ValueError:
            predicted_time = 'Calculation error'
    return jsonify(history=history, predicted_time=predicted_time)

@app.route('/get_devices')
@limiter.limit("60 per minute")
def get_devices():
    return jsonify(devices=state['devices'])

@app.route('/get_logs')
@limiter.limit("60 per minute")
def get_logs():
    return jsonify(logs=state['logs'][::-1])

@app.route('/wake_device', methods=['POST'])
@limiter.limit("10 per minute")
def wake_device_route():
    mac = request.get_json().get('mac')
    if not mac: return jsonify(success=False, message="MAC is required."), 400
    if send_wol(mac):
        return jsonify(success=True, message=f"WOL packet sent to {mac}.")
    return jsonify(success=False, message="WOL failed.")

@app.route('/add_device', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def add_device():
    if request.method == 'POST':
        name = request.form['name'].strip()
        mac = request.form.get('mac', '').strip().upper()
        ip = request.form['ip'].strip()
        existing_ips = {dev['ip'] for dev in state['devices']}
        existing_macs = {dev['mac'] for dev in state['devices'] if dev.get('mac')}

        if mac and not is_valid_mac(mac):
            flash('Error: Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.', 'error')
            return render_template('add_device.html', settings=state.get('settings', DEFAULT_SETTINGS), prefill_ip=ip, prefill_mac=mac)
        if not is_valid_ip(ip):
            flash('Error: Invalid IP address format. Please use a valid IPv4 address.', 'error')
            return render_template('add_device.html', settings=state.get('settings', DEFAULT_SETTINGS), prefill_ip=ip, prefill_mac=mac)

        if ip in existing_ips:
            flash(f'Error: A device with the IP address {ip} already exists.', 'error')
            return render_template('add_device.html', settings=state.get('settings', DEFAULT_SETTINGS), prefill_ip=ip, prefill_mac=mac)
        if mac and mac in existing_macs:
            flash(f'Error: A device with the MAC address {mac} already exists.', 'error')
            return render_template('add_device.html', settings=state.get('settings', DEFAULT_SETTINGS), prefill_ip=ip, prefill_mac=mac)

        if not mac:
            detected_mac = get_mac_from_ip(ip)
            if detected_mac:
                mac = detected_mac
                add_log(f"Auto-detected MAC for {ip}: {mac}", 'INFO')
            else:
                add_log(f"Could not auto-detect MAC for {ip}. Please enter it manually if needed for WOL.", 'WARNING')
                flash(f'Warning: Could not auto-detect MAC for {ip}. Device will be added without it.', 'warning')

        state['devices'].append({'name': name, 'mac': mac, 'ip': ip, 'online': False, 'last_seen': None})
        save_state()
        flash(f'Successfully added device: {name}', 'success')
        return redirect(url_for('dashboard'))

    prefill_ip = request.args.get('ip', '')
    prefill_mac = request.args.get('mac', '')
    return render_template('add_device.html', settings=state.get('settings', DEFAULT_SETTINGS), prefill_ip=prefill_ip, prefill_mac=prefill_mac)

@app.route('/add_selected_devices', methods=['POST'])
@limiter.limit("2 per minute")
def add_selected_devices():
    selected_devices = request.get_json()
    added_count, skipped_count = 0, 0
    existing_ips = {dev['ip'] for dev in state['devices']}
    existing_macs = {dev['mac'] for dev in state['devices'] if dev.get('mac')}
    for dev_info in selected_devices:
        ip = dev_info.get('ip')
        mac = dev_info.get('mac', '').strip().upper()
        if not ip or ip in existing_ips or (mac and mac in existing_macs):
            skipped_count += 1
            continue

        if mac and not is_valid_mac(mac):
            logger.warning(f"Skipping discovered device {ip} due to invalid MAC format: {mac}")
            skipped_count += 1
            continue
        if not is_valid_ip(ip):
            logger.warning(f"Skipping discovered device with invalid IP format: {ip}")
            skipped_count += 1
            continue

        name = dev_info.get('name') or f"Device-{ip.replace('.', '-')}"
        state['devices'].append({'name': name, 'mac': mac, 'ip': ip, 'online': False, 'last_seen': None})
        added_count += 1
    save_state()
    message = f"Added {added_count} device(s). Skipped {skipped_count}."
    flash(message, 'success' if added_count > 0 else 'warning')
    return jsonify(success=True, message=message)

@app.route('/remove_device', methods=['POST'])
@limiter.limit("10 per minute")
def remove_device():
    data = request.get_json()
    index = data.get('index')
    if index is None or not (0 <= index < len(state['devices'])):
        return jsonify(success=False, message="Device not found."), 404
    dev = state['devices'].pop(index)
    save_state()
    add_log(f'Removed device: {dev["name"]}', 'INFO')
    return jsonify(success=True, message=f'Device {dev["name"]} removed.')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'remove_ups' in request.args:
        try:
            index = int(request.args['remove_ups'])
            if 0 <= index < len(state['settings']['ups_configs']):
                removed = state['settings']['ups_configs'].pop(index)
                save_state()
                flash(f'UPS {removed["name"]} removed.', 'success')
            else:
                flash('Error: Invalid UPS index for removal.', 'error')
        except (ValueError, IndexError):
            flash('Error: Invalid UPS removal request.', 'error')
        return redirect(url_for('settings'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_ups':
            name, ip, port_str = request.form.get('ups_name'), request.form.get('ups_ip'), request.form.get('ups_port')

            try:
                port = int(port_str)
            except (ValueError, TypeError):
                flash('Error: UPS Port must be a valid number.', 'error')
                return redirect(url_for('settings'))

            if not name.strip() or not is_valid_ip(ip) or not (1 <= port <= 65535):
                flash('Error: All UPS fields are required and valid (Name, IP, Port 1-65535).', 'error')
                return redirect(url_for('settings'))

            if any(u['name'].lower() == name.strip().lower() for u in state['settings']['ups_configs']):
                flash(f'Error: UPS name "{name}" already exists.', 'error')
            else:
                state['settings']['ups_configs'].append({'name': name.strip(), 'ip': ip, 'port': port})
                flash(f"Added UPS: {name}", 'success')
        elif action == 'update_general':
            try:
                refresh_interval = int(request.form.get('refresh_interval', 30))
                log_retention = int(request.form.get('log_retention', 100))
                discovery_timeout = int(request.form.get('discovery_timeout', 2))
                wol_battery_threshold = int(request.form.get('wol_battery_threshold', 80))
            except ValueError:
                flash('Error: Please enter valid numbers for general settings.', 'error')
                return redirect(url_for('settings'))

            ip_scan_range = request.form.get('ip_scan_range', '192.168.1.0/24').strip()
            if not re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-9]|[1-2][0-9]|3[0-2]))?$', ip_scan_range):
                flash('Error: Invalid IP Scan Range format (e.g., 192.168.1.0/24 or 192.168.1.1).', 'error')
                return redirect(url_for('settings'))

            state['settings']['refresh_interval'] = refresh_interval
            state['settings']['log_retention'] = log_retention
            state['settings']['ip_scan_range'] = ip_scan_range
            state['settings']['discovery_timeout'] = discovery_timeout
            state['settings']['density'] = request.form.get('density', 'comfortable')
            state['settings']['wol_battery_threshold'] = wol_battery_threshold
            state['settings']['verbose_logging'] = request.form.get('verbose_logging') == 'true'
            flash('Settings saved.', 'success')
        save_state()
        return redirect(url_for('settings'))
    return render_template('settings.html', settings=state.get('settings', DEFAULT_SETTINGS))

@app.route('/edit_ups/<int:index>', methods=['GET', 'POST'])
def edit_ups(index):
    if not (0 <= index < len(state['settings']['ups_configs'])):
        flash('Error: UPS not found.', 'error')
        return redirect(url_for('settings'))

    ups_to_edit = state['settings']['ups_configs'][index]

    if request.method == 'POST':
        new_name = request.form['name'].strip()
        new_ip = request.form['ip'].strip()
        new_port_str = request.form['port'].strip()

        try:
            new_port = int(new_port_str)
        except (ValueError, TypeError):
            flash('Error: Port must be a valid number.', 'error')
            return render_template('edit_ups.html', settings=state.get('settings', DEFAULT_SETTINGS),
                                   ups=ups_to_edit, index=index)

        if not new_name.strip() or not is_valid_ip(new_ip) or not (1 <= new_port <= 65535):
            flash('Error: All fields are required and valid (Name, IP, Port 1-65535).', 'error')
            return render_template('edit_ups.html', settings=state.get('settings', DEFAULT_SETTINGS),
                                   ups=ups_to_edit, index=index)

        if any(u['name'].lower() == new_name.lower() and i != index
               for i, u in enumerate(state['settings']['ups_configs'])):
            flash(f'Error: UPS name "{new_name}" already exists.', 'error')
            return render_template('edit_ups.html', settings=state.get('settings', DEFAULT_SETTINGS),
                                   ups=ups_to_edit, index=index)

        ups_to_edit.update({'name': new_name, 'ip': new_ip, 'port': new_port})
        save_state()
        flash(f'Updated UPS: {new_name}', 'success')
        return redirect(url_for('settings'))

    return render_template('edit_ups.html', settings=state.get('settings', DEFAULT_SETTINGS),
                           ups=ups_to_edit, index=index)

@app.route('/discover')
@limiter.limit("2 per minute")
def discover():
    found_devices = discover_devices()
    added_ips = {dev['ip'] for dev in state['devices']}
    new_devices = [dev for dev in found_devices if dev['ip'] not in added_ips and dev.get('mac')]
    return render_template('discover.html', settings=state.get('settings', DEFAULT_SETTINGS), devices=new_devices)

@app.route('/device/<ip_address>')
def device_detail(ip_address):
    device = None
    device_index = -1
    for i, dev in enumerate(state['devices']):
        if dev['ip'] == ip_address:
            device = dev
            device_index = i
            break

    if not device:
        flash(f'Error: Device with IP {ip_address} not found.', 'error')
        return redirect(url_for('dashboard'))

    current_online_status = is_device_online(device['ip'])

    return render_template(
        'device_detail.html',
        settings=state.get('settings', DEFAULT_SETTINGS),
        device=device,
        current_online=current_online_status,
        index=device_index
    )

@app.route('/edit_device/<int:index>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def edit_device(index):
    if not (0 <= index < len(state['devices'])):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        mac = request.form.get('mac', '').strip().upper()
        ip = request.form['ip'].strip()

        if mac and not is_valid_mac(mac):
            flash('Error: Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.', 'error')
            return render_template('edit_device.html', settings=state.get('settings', DEFAULT_SETTINGS), device=state['devices'][index], index=index)
        if not is_valid_ip(ip):
            flash('Error: Invalid IP address format. Please use a valid IPv4 address.', 'error')
            return render_template('edit_device.html', settings=state.get('settings', DEFAULT_SETTINGS), device=state['devices'][index], index=index)

        if any(d['ip'] == ip and i != index for i, d in enumerate(state['devices'])):
            flash(f'Error: IP {ip} already exists.', 'error')
            return render_template('edit_device.html', settings=state.get('settings', DEFAULT_SETTINGS), device=state['devices'][index], index=index)
        state['devices'][index].update({'name': name, 'mac': mac, 'ip': ip})
        save_state()
        flash(f'Updated device: {name}', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_device.html', settings=state.get('settings', DEFAULT_SETTINGS), device=state['devices'][index], index=index)

if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    with app.app_context():
        load_state()
    threading.Thread(target=monitor_loop, daemon=True).start()
    serve(app, host='0.0.0.0', port=5000)