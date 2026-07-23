# LumenTrace v3 Django beta

V3 moves LumenTrace’s web and security layer from Flask to Django 5.2 LTS.
Stable v2 remains on Flask and is not changed by this beta.

## What changed

- Django authentication, sessions, CSRF protection, password validation, and
  database migrations
- first-run administrator setup
- administrator and read-only viewer roles
- Django-native scrypt password hashing
- local user management and command-line account recovery
- trusted-host validation, login throttling, hardened cookies, and security
  audit history
- automatic import from the earlier Flask-based v3 beta
- non-root production container using Waitress and WhiteNoise

The monitoring, outage capture, battery threshold, and Wake-on-LAN recovery
engine remains unchanged.

## Before installing

Back up the complete data directory:

```sh
cp -a ./data ./data-backup
```

Add the address used to open LumenTrace to `.env`:

```dotenv
ALLOWED_HOSTS=192.168.1.10
```

For Traefik:

```dotenv
ALLOWED_HOSTS=lumentrace.example.com
SESSION_COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
CSRF_TRUSTED_ORIGINS=https://lumentrace.example.com
```

## Install or update

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  up -d --pull always

docker compose logs --tail 100 lumentrace
```

The floating `pwsmith1988/lumentrace:v3` tag tracks the latest successful build
from `beta/v3`.

## Data migration

V2 users keep `/data/state.json` and create an administrator on first launch.

Users of the earlier Flask-based v3 beta are migrated automatically:

- `/data/auth.db` is read but not modified.
- users and audit records are copied to `/data/lumentrace.db`.
- existing passwords continue working.
- each legacy password is re-hashed by Django after the next successful login.

Do not delete `auth.db` or your backup until the Django beta has been verified.

## Roll back

The stable `latest` and v2 tags are not modified. Start the base Compose file
without the beta override:

```sh
docker compose -f docker-compose.yml up -d
```

V2 ignores `/data/lumentrace.db`. Preserve the whole data directory for a later
return to v3.
