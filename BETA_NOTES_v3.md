# LumenTrace v3 beta

The v3 beta introduces built-in local authentication while preserving existing
device, UPS, and recovery state.

## Included

- first-run administrator setup
- administrator and read-only viewer roles
- secure local login and logout
- scrypt password hashing
- account creation, disabling, and password reset
- security audit history
- CLI account recovery
- session invalidation after password changes or account disabling
- hardened cookies, CSRF protection, login throttling, and security headers

## Install the beta

Back up the complete data directory first. Then use the stable Compose file with
the beta override:

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  pull

docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  up -d
```

Open port 5000 and create the initial administrator. Existing `state.json` data
is retained; authentication is stored separately in `/data/auth.db`.

## Updating

The `pwsmith1988/lumentrace:v3` tag tracks the latest successful build from the
GitHub `beta/v3` branch:

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  pull

docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  up -d
```

## Roll back

The stable `latest` and v2 tags are not changed by beta publishing. To return to
v2.0.1, start the base Compose file without the beta override:

```sh
docker compose -f docker-compose.yml up -d
```

The v2 application ignores `auth.db`. Keep it with the backup for a later v3
upgrade.
