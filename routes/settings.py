import ipaddress

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for


settings_bp = Blueprint('settings', __name__)


def _bounded_integer(name, minimum, maximum, default):
    try:
        value = int(request.form.get(name, default))
    except (TypeError, ValueError):
        raise ValueError(f'{name.replace("_", " ").title()} must be a number.')
    if not minimum <= value <= maximum:
        raise ValueError(f'{name.replace("_", " ").title()} must be between {minimum} and {maximum}.')
    return value


@settings_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    manager = current_app.state_manager
    if request.method == 'POST':
        try:
            scan_range = request.form.get('ip_scan_range', '').strip()
            ipaddress.ip_network(scan_range, strict=False)
            updated = {
                'refresh_interval': _bounded_integer('refresh_interval', 5, 300, 30),
                'log_retention': _bounded_integer('log_retention', 25, 1000, 100),
                'wol_battery_threshold': _bounded_integer('wol_battery_threshold', 10, 100, 80),
                'discovery_timeout': _bounded_integer('discovery_timeout', 1, 15, 2),
                'ip_scan_range': scan_range,
                'verbose_logging': request.form.get('verbose_logging') == 'on',
            }
        except ValueError as error:
            flash(str(error), 'error')
        else:
            with manager.locked() as state:
                state['settings'].update(updated)
                manager.save()
            manager.add_log('Application settings updated.', 'INFO')
            flash('Settings saved.', 'success')
        return redirect(url_for('settings.settings'))

    return render_template('settings.html', settings=manager.get('settings', {}))
