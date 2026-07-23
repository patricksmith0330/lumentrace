# V3 Django security architecture

## Scope

LumenTrace v3 uses Django 5.2 LTS for:

- authentication and signed sessions
- scrypt password storage
- password validation
- CSRF protection
- user activation and session invalidation
- database schema migrations
- host-header validation
- secure-cookie and HTTPS-aware settings

The public `/api/health` endpoint remains available for container health checks.
All other pages and APIs require a valid session when `AUTH_MODE=local`.

## Authorization

Administrators can manage devices, UPS connections, settings, and users.
Viewers can read the dashboard, settings, and status APIs. Server-side checks
reject viewer writes even if a request is constructed outside the interface.

## Persistent storage

`/data/lumentrace.db` contains:

- Django users
- sessions
- schema migration state
- security audit events

`/data/state.json` continues to contain monitoring and recovery state.

## Earlier beta migration

At startup, `python manage.py migrate_flask_auth` checks for the earlier v3
beta’s `/data/auth.db`. It imports accounts only when the Django database has no
users. Werkzeug scrypt hashes are accepted by a verification-only compatibility
hasher and replaced with Django-native scrypt hashes after a successful login.

The source database remains untouched.

## Recovery commands

```sh
python manage.py lumentrace_user list
python manage.py lumentrace_user create USERNAME --role viewer
python manage.py lumentrace_user reset-password USERNAME
```

Inside Compose, prefix each command with:

```sh
docker compose exec lumentrace
```

## Deployment requirements

- Keep `SECRET_KEY` stable, private, and at least 32 characters.
- Configure `ALLOWED_HOSTS` with every accepted IP address and DNS name.
- Set `SESSION_COOKIE_SECURE=true` for HTTPS-only access.
- Enable `TRUST_PROXY_HEADERS=true` only behind a private trusted proxy.
- Set `CSRF_TRUSTED_ORIGINS` when the external HTTPS origin requires it.
- Back up `lumentrace.db` and `state.json` together.
- Do not expose port 5000 directly to the public internet.
- Treat `AUTH_MODE=disabled` as a temporary emergency bypass.
