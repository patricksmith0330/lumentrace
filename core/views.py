import ipaddress
import json
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, logout, update_session_auth_hash
from django.db import transaction
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from config import DEFAULT_SETTINGS, RATE_LIMITS
from core.auth_utils import (
    admin_required,
    audit,
    create_user,
    display_name,
    role_name,
    safe_next_url,
    validate_password,
)
from core.models import AuditEvent
from core.rate_limit import rate_limit
from core.runtime import manager
from models import find_ups_by_id, generate_ups_id
from utils.analytics import predict_battery_time
from utils.network import (
    discover_devices,
    get_mac_from_ip,
    is_device_online,
    is_valid_ip,
    is_valid_mac,
    send_wol,
)
from utils.ups import get_ups_data, test_ups_connection


logger = logging.getLogger(__name__)


def _json_body(request):
    try:
        value = json.loads(request.body or b'{}')
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value


def _json(payload, status=200):
    return JsonResponse(payload, status=status, safe=not isinstance(payload, list))


def csrf_failure(request, reason=''):
    if request.path.startswith('/api/'):
        return _json({'success': False, 'message': 'Security token expired. Refresh and try again.'}, 403)
    return HttpResponseForbidden('Security token expired.')


@require_GET
def health(request):
    return _json({'status': 'ok'})


@require_http_methods(['GET', 'POST'])
@rate_limit(RATE_LIMITS['setup'], methods=['POST'])
def setup(request):
    if settings.AUTH_MODE == 'disabled':
        return redirect('dashboard')
    User = get_user_model()
    if User.objects.exists():
        return redirect('login')
    if request.method == 'POST':
        password = request.POST.get('password', '')
        if password != request.POST.get('password_confirm', ''):
            messages.error(request, 'Passwords do not match.')
        else:
            try:
                with transaction.atomic():
                    if User.objects.exists():
                        raise ValueError('Administrator setup has already been completed.')
                    user = create_user(
                        request.POST.get('username', ''),
                        password,
                        request.POST.get('display_name', ''),
                        'admin',
                    )
            except ValueError as error:
                messages.error(request, str(error))
            else:
                login(request, user)
                audit('account.initial_admin_created', request=request, actor=user, target=user.username)
                messages.success(request, 'Administrator account created.')
                return redirect('dashboard')
    return render(request, 'auth/setup.html')


@require_http_methods(['GET', 'POST'])
@rate_limit(RATE_LIMITS['login'], methods=['POST'])
def login_view(request):
    if settings.AUTH_MODE == 'disabled':
        return redirect('dashboard')
    if not get_user_model().objects.exists():
        return redirect('setup')
    if request.user.is_authenticated:
        return redirect('dashboard')
    next_url = safe_next_url(request.GET.get('next') or request.POST.get('next'))
    if request.method == 'POST':
        username = str(request.POST.get('username', '')).strip().lower()
        user = authenticate(request, username=username, password=request.POST.get('password', ''))
        if user is not None:
            login(request, user)
            audit('auth.login_succeeded', request=request, actor=user)
            return redirect(next_url or 'dashboard')
        audit('auth.login_failed', request=request, actor_username=username[:64])
        messages.error(request, 'The username or password is incorrect.')
    return render(request, 'auth/login.html', {'next_url': next_url or ''})


@require_POST
def logout_view(request):
    actor = request.user if request.user.is_authenticated else None
    audit('auth.logout', request=request, actor=actor)
    logout(request)
    messages.success(request, 'You have been signed out.')
    return redirect('login')


@require_http_methods(['GET', 'POST'])
def account(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '')
        replacement = request.POST.get('password', '')
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
        elif replacement != request.POST.get('password_confirm', ''):
            messages.error(request, 'New passwords do not match.')
        else:
            try:
                validate_password(replacement, request.user)
            except ValueError as error:
                messages.error(request, str(error))
            else:
                request.user.set_password(replacement)
                request.user.save(update_fields=['password'])
                update_session_auth_hash(request, request.user)
                audit('account.password_changed', request=request, target=request.user.username)
                messages.success(request, 'Password changed.')
                return redirect('account')
    return render(request, 'auth/account.html')


@require_http_methods(['GET', 'POST'])
@admin_required
def users(request):
    if request.method == 'POST':
        password = request.POST.get('password', '')
        if password != request.POST.get('password_confirm', ''):
            messages.error(request, 'Passwords do not match.')
        else:
            try:
                user = create_user(
                    request.POST.get('username', ''),
                    password,
                    request.POST.get('display_name', ''),
                    request.POST.get('role', 'viewer'),
                )
            except ValueError as error:
                messages.error(request, str(error))
            else:
                audit(
                    'account.created',
                    request=request,
                    target=user.username,
                    details={'role': role_name(user)},
                )
                messages.success(request, f'Created {user.username}.')
                return redirect('users')
    return render(
        request,
        'auth/users.html',
        {
            'managed_users': get_user_model().objects.order_by('-is_staff', 'username'),
            'audit_events': AuditEvent.objects.select_related('actor')[:50],
        },
    )


@require_POST
@admin_required
def toggle_user(request, user_id):
    try:
        user = get_user_model().objects.get(pk=user_id)
    except get_user_model().DoesNotExist as error:
        raise Http404 from error
    if user.pk == request.user.pk:
        messages.error(request, 'You cannot disable your own account.')
    elif user.is_staff and user.is_active and get_user_model().objects.filter(
        is_staff=True, is_active=True
    ).count() <= 1:
        messages.error(request, 'At least one active administrator is required.')
    else:
        user.is_active = not user.is_active
        user.save(update_fields=['is_active'])
        action = 'enabled' if user.is_active else 'disabled'
        audit(f'account.{action}', request=request, target=user.username)
        messages.success(request, f'{user.username} {action}.')
    return redirect('users')


@require_POST
@admin_required
def reset_user_password(request, user_id):
    try:
        user = get_user_model().objects.get(pk=user_id)
    except get_user_model().DoesNotExist as error:
        raise Http404 from error
    password = request.POST.get('password', '')
    if password != request.POST.get('password_confirm', ''):
        messages.error(request, 'Passwords do not match.')
    else:
        try:
            validate_password(password, user)
        except ValueError as error:
            messages.error(request, str(error))
        else:
            user.set_password(password)
            user.save(update_fields=['password'])
            if user.pk == request.user.pk:
                update_session_auth_hash(request, user)
            audit('account.password_reset', request=request, target=user.username)
            messages.success(request, f'Reset the password for {user.username}.')
    return redirect('users')


@require_GET
def dashboard(request):
    return render(
        request,
        'dashboard.html',
        {'settings': manager.get('settings', DEFAULT_SETTINGS)},
    )


@require_GET
@rate_limit(RATE_LIMITS['api_read'])
def dashboard_data(request):
    snapshot = manager.snapshot()
    app_settings = snapshot.get('settings', {})
    history = snapshot.get('battery_history', [])
    predicted_time = predict_battery_time(history) if len(history) >= 2 else 'Insufficient data'
    return _json({
        'ups_systems': get_ups_data(app_settings.get('ups_configs', []), manager),
        'devices': snapshot.get('devices', []),
        'logs': snapshot.get('logs', [])[-30:][::-1],
        'recovery_state': snapshot.get('recovery_state', 'NORMAL'),
        'predicted_time': predicted_time,
        'battery_history': history,
    })


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


@require_POST
@rate_limit(RATE_LIMITS['device_action'])
@admin_required
def wake_device(request):
    data = _json_body(request)
    mac = str(data.get('mac', '')).strip().upper().replace('-', ':')
    if not is_valid_mac(mac):
        return _json({'success': False, 'message': 'A valid MAC address is required.'}, 400)
    if send_wol(mac, manager):
        return _json({'success': True, 'message': 'Wake packet sent.'})
    return _json({'success': False, 'message': 'The wake packet could not be sent.'}, 500)


@require_http_methods(['GET', 'POST'])
@rate_limit(RATE_LIMITS['api_write'], methods=['POST'])
@admin_required
def add_device(request):
    app_settings = manager.get('settings', {})
    initial = {
        'name': request.POST.get('name', ''),
        'ip': request.POST.get('ip', request.GET.get('ip', '')),
        'mac': request.POST.get('mac', request.GET.get('mac', '')),
    }
    if request.method == 'POST':
        with manager.locked() as state:
            device, error = _validated_device(request.POST, state.get('devices', []))
            if error:
                messages.error(request, error)
                return render(request, 'add_device.html', {'settings': app_settings, 'initial': initial, 'submit_label': 'Add device'})
            if not device['mac']:
                device['mac'] = get_mac_from_ip(device['ip']) or ''
                if not device['mac']:
                    messages.warning(request, 'Device added without a MAC address. Wake-on-LAN will be unavailable.')
            device.update(online=False, last_seen=None)
            state['devices'].append(device)
            manager.save()
        manager.add_log(f"Added device: {device['name']}", 'INFO')
        messages.success(request, f"Added {device['name']}.")
        return redirect('dashboard')
    return render(request, 'add_device.html', {'settings': app_settings, 'initial': initial, 'submit_label': 'Add device'})


@require_http_methods(['GET', 'POST'])
@rate_limit(RATE_LIMITS['api_write'], methods=['POST'])
@admin_required
def edit_device(request, index):
    app_settings = manager.get('settings', {})
    devices = manager.get('devices', [])
    if not 0 <= index < len(devices):
        messages.error(request, 'Device not found.')
        return redirect('dashboard')
    if request.method == 'POST':
        with manager.locked() as state:
            device, error = _validated_device(request.POST, state['devices'], current_index=index)
            if error:
                messages.error(request, error)
                initial = {**state['devices'][index], **request.POST.dict()}
                return render(request, 'edit_device.html', {'settings': app_settings, 'initial': initial, 'index': index, 'submit_label': 'Save changes'})
            state['devices'][index].update(device)
            manager.save()
        manager.add_log(f"Updated device: {device['name']}", 'INFO')
        messages.success(request, f"Updated {device['name']}.")
        return redirect('dashboard')
    return render(request, 'edit_device.html', {'settings': app_settings, 'initial': devices[index], 'index': index, 'submit_label': 'Save changes'})


@require_POST
@rate_limit(RATE_LIMITS['device_action'])
@admin_required
def remove_device(request):
    data = _json_body(request)
    index = data.get('index')
    with manager.locked() as state:
        devices = state.get('devices', [])
        if not isinstance(index, int) or not 0 <= index < len(devices):
            return _json({'success': False, 'message': 'Device not found.'}, 404)
        removed = devices.pop(index)
        state.get('uptime_stats', {}).pop(removed.get('ip'), None)
        manager.save()
    manager.add_log(f"Removed device: {removed['name']}", 'INFO')
    return _json({'success': True, 'message': f"Removed {removed['name']}."})


@require_GET
@admin_required
def discover(request):
    return render(request, 'discover.html', {'settings': manager.get('settings', {})})


@require_POST
@rate_limit(RATE_LIMITS['discovery'])
@admin_required
def scan_network(request):
    app_settings = manager.get('settings', {})
    found = discover_devices(
        app_settings.get('ip_scan_range', '192.168.1.0/24'),
        app_settings.get('discovery_timeout', 2),
        manager,
    )
    existing_ips = {device['ip'] for device in manager.get('devices', [])}
    devices = [item for item in found if item.get('ip') not in existing_ips and item.get('mac')]
    return _json({'success': True, 'devices': devices})


@require_POST
@rate_limit(RATE_LIMITS['discovery'])
@admin_required
def add_selected_devices(request):
    selected = _json_body(request)
    if not isinstance(selected, list):
        return _json({'success': False, 'message': 'Select at least one device.'}, 400)
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
    return _json({'success': True, 'message': f'Added {added} device(s); skipped {skipped}.'})


@require_GET
@rate_limit(RATE_LIMITS['api_read'])
def device_status(request, ip):
    if not is_valid_ip(ip):
        return _json({'online': False, 'last_seen': None}, 400)
    device = next((item for item in manager.get('devices', []) if item.get('ip') == ip), None)
    if not device:
        return _json({'online': False, 'last_seen': None}, 404)
    online = is_device_online(ip, manager)
    with manager.locked():
        device['online'] = online
        manager.save()
    return _json({'online': online, 'last_seen': device.get('last_seen')})


@require_GET
@rate_limit(RATE_LIMITS['api_read'])
def discover_mac(request):
    ip = request.GET.get('ip', '')
    if not is_valid_ip(ip):
        return _json({'success': False, 'message': 'Enter a valid IP address.'}, 400)
    mac = get_mac_from_ip(ip)
    if not mac:
        return _json({'success': False, 'message': 'No MAC address was found.'}, 404)
    return _json({'success': True, 'mac': mac, 'message': 'MAC address found.'})


def _bounded_integer(form, name, minimum, maximum, default):
    try:
        value = int(form.get(name, default))
    except (TypeError, ValueError) as error:
        raise ValueError(f'{name.replace("_", " ").title()} must be a number.') from error
    if not minimum <= value <= maximum:
        raise ValueError(f'{name.replace("_", " ").title()} must be between {minimum} and {maximum}.')
    return value


@require_http_methods(['GET', 'POST'])
def settings_view(request):
    if request.method == 'POST':
        if settings.AUTH_MODE != 'disabled' and not request.user.is_staff:
            return HttpResponseForbidden()
        try:
            scan_range = request.POST.get('ip_scan_range', '').strip()
            ipaddress.ip_network(scan_range, strict=False)
            updated = {
                'refresh_interval': _bounded_integer(request.POST, 'refresh_interval', 5, 300, 30),
                'log_retention': _bounded_integer(request.POST, 'log_retention', 25, 1000, 100),
                'wol_battery_threshold': _bounded_integer(request.POST, 'wol_battery_threshold', 10, 100, 80),
                'discovery_timeout': _bounded_integer(request.POST, 'discovery_timeout', 1, 15, 2),
                'ip_scan_range': scan_range,
                'verbose_logging': request.POST.get('verbose_logging') == 'on',
            }
        except ValueError as error:
            messages.error(request, str(error))
        else:
            with manager.locked() as state:
                state['settings'].update(updated)
                manager.save()
            manager.add_log('Application settings updated.', 'INFO')
            messages.success(request, 'Settings saved.')
        return redirect('settings')
    return render(request, 'settings.html', {'settings': manager.get('settings', {})})


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


@require_POST
@rate_limit(RATE_LIMITS['api_write'])
@admin_required
def add_ups(request):
    payload, error = _ups_payload(_json_body(request))
    if error:
        return _json({'success': False, 'message': error}, 400)
    with manager.locked() as state:
        configs = state['settings']['ups_configs']
        if any(item['name'].lower() == payload['name'].lower() for item in configs):
            return _json({'success': False, 'message': 'A UPS with that name already exists.'}, 409)
        payload['id'] = generate_ups_id(payload['name'], payload['ip'])
        configs.append(payload)
        manager.save()
    manager.add_log(f"Added UPS: {payload['name']}", 'INFO')
    return _json({'success': True, 'message': 'UPS added.', 'ups': payload}, 201)


@require_http_methods(['PUT', 'DELETE'])
@rate_limit(RATE_LIMITS['api_write'])
@admin_required
def update_ups(request, ups_id):
    if request.method == 'DELETE':
        with manager.locked() as state:
            index, ups = find_ups_by_id(state, ups_id)
            if ups is None:
                return _json({'success': False, 'message': 'UPS not found.'}, 404)
            removed = state['settings']['ups_configs'].pop(index)
            manager.save()
        manager.add_log(f"Removed UPS: {removed['name']}", 'INFO')
        return _json({'success': True, 'message': 'UPS removed.'})

    payload, error = _ups_payload(_json_body(request))
    if error:
        return _json({'success': False, 'message': error}, 400)
    with manager.locked() as state:
        index, ups = find_ups_by_id(state, ups_id)
        if ups is None:
            return _json({'success': False, 'message': 'UPS not found.'}, 404)
        configs = state['settings']['ups_configs']
        if any(i != index and item['name'].lower() == payload['name'].lower() for i, item in enumerate(configs)):
            return _json({'success': False, 'message': 'A UPS with that name already exists.'}, 409)
        configs[index].update(payload)
        manager.save()
    manager.add_log(f"Updated UPS: {payload['name']}", 'INFO')
    return _json({'success': True, 'message': 'UPS updated.'})


@require_POST
@rate_limit(RATE_LIMITS['device_action'])
@admin_required
def test_ups(request):
    payload, error = _ups_payload(_json_body(request))
    if error:
        return _json({'success': False, 'message': error}, 400)
    success, message = test_ups_connection(payload)
    return _json({'success': success, 'message': message}, 200 if success else 422)


@require_GET
@rate_limit(RATE_LIMITS['api_read'])
def ups_status(request):
    configs = manager.get('settings', {}).get('ups_configs', [])
    return _json({'ups_systems': get_ups_data(configs, manager)})
