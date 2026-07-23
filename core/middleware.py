from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.shortcuts import redirect, render

from core.auth_utils import audit


SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}


class AccessControlMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.AUTH_MODE == 'disabled':
            return self.get_response(request)

        path = request.path
        exempt = (
            path == '/api/health'
            or path.startswith('/static/')
            or path in {'/login', '/setup'}
        )
        if exempt:
            return self.get_response(request)

        if not get_user_model().objects.exists():
            if path.startswith('/api/'):
                return JsonResponse(
                    {'success': False, 'message': 'Administrator setup is required.'},
                    status=503,
                )
            return redirect('/setup')

        if not request.user.is_authenticated:
            if path.startswith('/api/'):
                return JsonResponse(
                    {'success': False, 'message': 'Authentication required.'},
                    status=401,
                )
            return redirect(f"/login?{urlencode({'next': request.get_full_path()})}")

        account_write = path in {'/account', '/logout'}
        if request.method not in SAFE_METHODS and not request.user.is_staff and not account_write:
            if path.startswith('/api/'):
                return JsonResponse(
                    {'success': False, 'message': 'Administrator access is required.'},
                    status=403,
                )
            return render(request, 'errors/403.html', status=403)

        response = self.get_response(request)
        if (
            request.method not in SAFE_METHODS
            and request.user.is_authenticated
            and not path.startswith(('/login', '/logout', '/setup', '/account', '/users'))
            and response.status_code < 400
        ):
            audit(
                'application.write',
                request=request,
                target=getattr(request.resolver_match, 'url_name', path),
                details={'method': request.method, 'status': response.status_code},
            )
        return response


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        authenticated = getattr(getattr(request, 'user', None), 'is_authenticated', False)
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'",
        )
        response.headers.setdefault(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=()',
        )
        if request.path.startswith(('/login', '/setup', '/account', '/users')) or (
            settings.AUTH_MODE == 'local' and authenticated
        ):
            response.headers['Cache-Control'] = 'no-store'
        return response
