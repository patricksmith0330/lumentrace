from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from models import generate_ups_id
from utils.network import is_valid_ip
import json
import re

settings_bp = Blueprint('settings', __name__)

def get_state_manager():
    return current_app.state_manager

@settings_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    state_manager = get_state_manager()
    
    if 'remove_ups' in request.args:
        try:
            index = int(request.args['remove_ups'])
            settings = state_manager.get('settings', {})
            ups_configs = settings.get('ups_configs', [])
            if 0 <= index < len(ups_configs):
                removed = ups_configs.pop(index)
                state_manager.save()
                flash(f'UPS {removed["name"]} removed.', 'success')
            else:
                flash('Error: Invalid UPS index for removal.', 'error')
        except (ValueError, IndexError):
            flash('Error: Invalid UPS removal request.', 'error')
        return redirect(url_for('settings.settings'))

    if request.method == 'POST':
        action = request.form.get('action')
        settings = state_manager.get('settings', {})
        
        if action == 'add_ups':
            name = request.form.get('ups_name')
            ip = request.form.get('ups_ip')
            port_str = request.form.get('ups_port')

            try:
                port = int(port_str)
            except (ValueError, TypeError):
                flash('Error: UPS Port must be a valid number.', 'error')
                return redirect(url_for('settings.settings'))

            if not name.strip() or not is_valid_ip(ip) or not (1 <= port <= 65535):
                flash('Error: All UPS fields are required and valid (Name, IP, Port 1-65535).', 'error')
                return redirect(url_for('settings.settings'))

            if any(u['name'].lower() == name.strip().lower() for u in settings.get('ups_configs', [])):
                flash(f'Error: UPS name "{name}" already exists.', 'error')
            else:
                new_ups = {
                    'id': generate_ups_id(name.strip(), ip),
                    'name': name.strip(), 
                    'ip': ip, 
                    'port': port
                }
                settings['ups_configs'].append(new_ups)
                flash(f"Added UPS: {name}", 'success')
                
        elif action == 'update_ups_inline':
            ups_configs_json = request.form.get('ups_configs')
            if ups_configs_json:
                try:
                    new_ups_configs = json.loads(ups_configs_json)
                    for ups in new_ups_configs:
                        if not ups.get('name', '').strip() or not is_valid_ip(ups.get('ip', '')) or not (1 <= ups.get('port', 0) <= 65535):
                            flash('Error: Invalid UPS configuration', 'error')
                            return redirect(url_for('settings.settings'))
                        if 'id' not in ups:
                            ups['id'] = generate_ups_id(ups['name'], ups['ip'])
                    
                    settings['ups_configs'] = new_ups_configs
                    flash('UPS configuration updated successfully', 'success')
                except json.JSONDecodeError:
                    flash('Error: Invalid configuration data', 'error')
                    
        elif action == 'update_general':
            try:
                refresh_interval = int(request.form.get('refresh_interval', 30))
                log_retention = int(request.form.get('log_retention', 100))
                discovery_timeout = int(request.form.get('discovery_timeout', 2))
                wol_battery_threshold = int(request.form.get('wol_battery_threshold', 80))
            except ValueError:
                flash('Error: Please enter valid numbers for general settings.', 'error')
                return redirect(url_for('settings.settings'))

            ip_scan_range = request.form.get('ip_scan_range', '192.168.1.0/24').strip()
            if not re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-9]|[1-2][0-9]|3[0-2]))?$', ip_scan_range):
                flash('Error: Invalid IP Scan Range format (e.g., 192.168.1.0/24 or 192.168.1.1).', 'error')
                return redirect(url_for('settings.settings'))

            settings['refresh_interval'] = refresh_interval
            settings['log_retention'] = log_retention
            settings['ip_scan_range'] = ip_scan_range
            settings['discovery_timeout'] = discovery_timeout
            settings['density'] = request.form.get('density', 'comfortable')
            settings['wol_battery_threshold'] = wol_battery_threshold
            settings['verbose_logging'] = request.form.get('verbose_logging') == 'true'
            settings['theme'] = request.form.get('theme', 'dark')
            flash('Settings saved.', 'success')
            
        state_manager.save()
        return redirect(url_for('settings.settings'))
        
    return render_template('settings.html', settings=state_manager.get('settings', {}))

@settings_bp.route('/edit_ups/<int:index>', methods=['GET', 'POST'])
def edit_ups(index):
    state_manager = get_state_manager()
    settings = state_manager.get('settings', {})
    ups_configs = settings.get('ups_configs', [])
    
    if not (0 <= index < len(ups_configs)):
        flash('Error: UPS not found.', 'error')
        return redirect(url_for('settings.settings'))

    ups_to_edit = ups_configs[index]

    if request.method == 'POST':
        new_name = request.form['name'].strip()
        new_ip = request.form['ip'].strip()
        new_port_str = request.form['port'].strip()

        try:
            new_port = int(new_port_str)
        except (ValueError, TypeError):
            flash('Error: Port must be a valid number.', 'error')
            return render_template('edit_ups.html', settings=settings,
                                   ups=ups_to_edit, index=index)

        if not new_name.strip() or not is_valid_ip(new_ip) or not (1 <= new_port <= 65535):
            flash('Error: All fields are required and valid (Name, IP, Port 1-65535).', 'error')
            return render_template('edit_ups.html', settings=settings,
                                   ups=ups_to_edit, index=index)

        if any(u['name'].lower() == new_name.lower() and i != index
               for i, u in enumerate(ups_configs)):
            flash(f'Error: UPS name "{new_name}" already exists.', 'error')
            return render_template('edit_ups.html', settings=settings,
                                   ups=ups_to_edit, index=index)

        ups_to_edit.update({'name': new_name, 'ip': new_ip, 'port': new_port})
        if 'id' not in ups_to_edit:
            ups_to_edit['id'] = generate_ups_id(new_name, new_ip)
        state_manager.save()
        flash(f'Updated UPS: {new_name}', 'success')
        return redirect(url_for('settings.settings'))

    return render_template('edit_ups.html', settings=settings,
                           ups=ups_to_edit, index=index)