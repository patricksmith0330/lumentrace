import hashlib
import re
import time
from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse

from core.auth_utils import client_ip


RATE_PATTERN = re.compile(r'^(?P<count>\d+) per (?P<period>second|minute|hour)$')
PERIOD_SECONDS = {'second': 1, 'minute': 60, 'hour': 3600}


def rate_limit(rate, methods=None):
    match = RATE_PATTERN.match(rate)
    if not match:
        raise ValueError(f'Unsupported rate limit: {rate}')
    limit = int(match.group('count'))
    window = PERIOD_SECONDS[match.group('period')]
    limited_methods = {method.upper() for method in methods} if methods else None

    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not getattr(settings, 'RATELIMIT_ENABLED', True):
                return view(request, *args, **kwargs)
            if limited_methods and request.method not in limited_methods:
                return view(request, *args, **kwargs)
            bucket = int(time.time() // window)
            identity = client_ip(request) or 'unknown'
            raw_key = f'{view.__module__}.{view.__name__}:{identity}:{bucket}'
            key = f'ratelimit:{hashlib.sha256(raw_key.encode()).hexdigest()}'
            if cache.add(key, 1, timeout=window + 1):
                count = 1
            else:
                try:
                    count = cache.incr(key)
                except ValueError:
                    cache.set(key, 1, timeout=window + 1)
                    count = 1
            if count > limit:
                return JsonResponse(
                    {'success': False, 'message': 'Too many requests. Try again shortly.'},
                    status=429,
                )
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
