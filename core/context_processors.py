from django.conf import settings

from core.auth_utils import display_name, role_name


def shell_context(request):
    authenticated = request.user.is_authenticated
    return {
        'auth_mode': settings.AUTH_MODE,
        'can_manage': settings.AUTH_MODE == 'disabled' or (
            authenticated and request.user.is_staff
        ),
        'display_name': display_name(request.user) if authenticated else '',
        'role_name': role_name(request.user) if authenticated else '',
        'page_namespace': getattr(getattr(request, 'resolver_match', None), 'namespace', ''),
        'page_name': getattr(getattr(request, 'resolver_match', None), 'url_name', ''),
    }
