import ipaddress
import re
from functools import wraps
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password as django_validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import render

from core.models import AuditEvent


USERNAME_PATTERN = re.compile(r'^[a-z0-9._-]+$')


def normalize_username(value):
    return str(value or '').strip().lower()


def validate_username(value):
    username = normalize_username(value)
    if not 3 <= len(username) <= 64:
        raise ValueError('Username must be between 3 and 64 characters.')
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError('Username may only contain letters, numbers, periods, dashes, and underscores.')
    return username


def validate_password(password, user=None):
    if len(password or '') > 128:
        raise ValueError('Password must be 128 characters or fewer.')
    try:
        django_validate_password(password, user=user)
    except ValidationError as error:
        raise ValueError(' '.join(error.messages)) from error
    return password


def display_name(user):
    return (user.get_full_name() or user.username).strip()


def role_name(user):
    return 'admin' if user.is_staff else 'viewer'


def create_user(username, password, display='', role='viewer'):
    username = validate_username(username)
    if role not in {'admin', 'viewer'}:
        raise ValueError('Choose a valid account role.')
    display = str(display or '').strip() or username
    if len(display) > 80:
        raise ValueError('Display name must be 80 characters or fewer.')
    User = get_user_model()
    if User.objects.filter(username__iexact=username).exists():
        raise ValueError('That username is already in use.')
    candidate = User(username=username, first_name=display, is_staff=role == 'admin')
    validate_password(password, candidate)
    candidate.set_password(password)
    candidate.save()
    return candidate


def safe_next_url(value):
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith('/'):
        return None
    return parsed.path + (f'?{parsed.query}' if parsed.query else '')


def client_ip(request):
    value = request.META.get('REMOTE_ADDR', '')
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            value = forwarded.split(',', 1)[0].strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def audit(event_type, request=None, actor=None, target='', details=None, actor_username=''):
    if actor is None and request is not None and request.user.is_authenticated:
        actor = request.user
    AuditEvent.objects.create(
        actor=actor if getattr(actor, 'is_authenticated', False) else None,
        actor_username=actor_username or getattr(actor, 'username', ''),
        event_type=event_type,
        target=str(target or '')[:255],
        details=details or {},
        remote_address=client_ip(request) if request is not None else None,
    )


def admin_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if settings.AUTH_MODE == 'disabled' or (
            request.user.is_authenticated and request.user.is_staff
        ):
            return view(request, *args, **kwargs)
        if request.path.startswith('/api/'):
            return JsonResponse(
                {'success': False, 'message': 'Administrator access is required.'},
                status=403,
            )
        messages.error(request, 'Administrator access is required.')
        return render(request, 'errors/403.html', status=403)

    return wrapped
