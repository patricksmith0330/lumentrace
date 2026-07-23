# LumenTrace

**Automated power recovery for your network.**

LumenTrace monitors Network UPS Tools (NUT) servers, remembers which devices
were online when an outage began, and uses Wake-on-LAN to bring them back after
utility power is stable and the UPS batteries have recharged.

![LumenTrace system overview](docs/images/lumentrace-dashboard.png)

> This branch contains the Django-based v3 beta. Stable v2 remains available as
> `pwsmith1988/lumentrace:2.0.1` and `pwsmith1988/lumentrace:latest`.

## Why LumenTrace?

A conventional Wake-on-LAN tool can turn on a machine, but it does not know
whether that machine was running before a power failure or whether the UPS is
ready to support it again. LumenTrace adds that missing recovery workflow:

1. Monitor every configured UPS and device.
2. Capture the online devices when an outage begins.
3. Persist that recovery list even if the LumenTrace host restarts.
4. Wait until every UPS is back online and above the chosen battery threshold.
5. Send Wake-on-LAN packets only to the devices that were previously online.

## V3 beta features

- Django 5.2 LTS security foundation
- First-run administrator setup with no public registration
- Administrator and read-only viewer roles
- Scrypt password hashing and transparent legacy-hash upgrades
- CSRF protection, login throttling, trusted-host validation, and audit history
- Session invalidation after password reset or account disablement
- Multiple NUT/UPS connections and persistent recovery states
- Manual and automatic Wake-on-LAN
- Device monitoring, discovery, and last-seen history
- Atomic state writes with a rolling backup
- Non-root, read-only application process with tightly scoped startup capabilities
- `linux/amd64` and `linux/arm64` images

## Try the v3 beta

Save `docker-compose.yml`, `docker-compose.v3-beta.yml`, and `.env.example` in
the same directory. Then create the environment file:

```sh
cp .env.example .env
openssl rand -hex 48
```

Paste the generated value and the address you use to open LumenTrace:

```dotenv
SECRET_KEY=replace-with-your-generated-value
ALLOWED_HOSTS=192.168.1.10
TZ=America/New_York
POLL_INTERVAL=10
```

Start the beta:

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  up -d --pull always
```

Open `http://YOUR-SERVER-IP:5000`. LumenTrace will ask you to create the first
administrator.

Host networking lets ARP discovery and broadcast Wake-on-LAN reach the local
network. No `ports:` entry is required because LumenTrace listens directly on
host TCP port `5000`. The container briefly uses `CHOWN`, `SETUID`, and
`SETGID` during startup to secure the bind-mounted data directory, then runs
the application as UID/GID `10001`. `NET_RAW` supports discovery and ping.

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `SECRET_KEY` | Yes | — | At least 32 characters; protects sessions and security tokens |
| `ALLOWED_HOSTS` | Yes for remote access | Localhost only | Comma-separated IP addresses and DNS names accepted by LumenTrace |
| `AUTH_MODE` | No | `local` | `local` enables authentication; `disabled` is an emergency bypass |
| `SESSION_LIFETIME_MINUTES` | No | `480` | Signed-in session lifetime |
| `SESSION_COOKIE_SECURE` | No | `false` | Set to `true` when access is HTTPS-only |
| `TRUST_PROXY_HEADERS` | No | `false` | Trust forwarded host, protocol, and client details from a private reverse proxy |
| `CSRF_TRUSTED_ORIGINS` | No | — | Comma-separated HTTPS origins when required by a reverse-proxy deployment |
| `TZ` | No | `America/New_York` | Container timezone |
| `POLL_INTERVAL` | No | `10` | Background monitoring interval in seconds |
| `DATA_DIR` | No | `/data` | Persistent application-data directory |

Do not commit `.env`, use the example secret, or expose `AUTH_MODE=disabled` to
an untrusted network.

## Upgrading

Back up the complete data directory:

```sh
cp -a ./data ./data-backup
```

Then pull and restart:

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.v3-beta.yml \
  up -d --pull always

docker compose logs --tail 100 lumentrace
```

Existing `/data/state.json` device, UPS, and recovery data is retained.

If you already tested the earlier Flask-based v3 beta, startup automatically
imports its `/data/auth.db` users and audit history into
`/data/lumentrace.db`. Existing passwords continue working and are upgraded to
Django’s native scrypt format on the next successful login. The old database is
left untouched as a rollback artifact.

## Account recovery

List users:

```sh
docker compose exec lumentrace \
  python manage.py lumentrace_user list
```

Create a user:

```sh
docker compose exec lumentrace \
  python manage.py lumentrace_user create USERNAME --role viewer
```

Reset a password:

```sh
docker compose exec lumentrace \
  python manage.py lumentrace_user reset-password USERNAME
```

## Data and recovery

- `/data/state.json` stores devices, UPS settings, recovery state, and activity.
- `/data/state.json.bak` is the previous valid state snapshot.
- `/data/lumentrace.db` stores Django users, sessions, migrations, and audit
  records.
- `/data/auth.db` is retained only when imported from an earlier v3 beta.

The dashboard reports:

- **Ready** — normal monitoring
- **Outage captured** — previously online devices have been recorded
- **Waiting for recharge** — utility power is back but a UPS is not ready
- **Waking devices** — recovery packets are being sent

## Traefik and HTTPS

Do not expose port `5000` directly to the public internet. Put LumenTrace behind
Traefik or another HTTPS reverse proxy.

Because LumenTrace uses host networking, a bridge-networked Traefik container
should route to the Docker host:

```yaml
http:
  services:
    lumentrace:
      loadBalancer:
        servers:
          - url: http://host.docker.internal:5000
```

On Linux, add `host.docker.internal:host-gateway` to the Traefik container if
the alias is unavailable.

For an HTTPS deployment:

```dotenv
ALLOWED_HOSTS=lumentrace.example.com
SESSION_COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
CSRF_TRUSTED_ORIGINS=https://lumentrace.example.com
```

Only enable forwarded-header trust when the LumenTrace port is reachable
exclusively through your trusted proxy.

## Roll back to v2

The beta workflow never changes `latest`. Start the base Compose file without
the beta override:

```sh
docker compose -f docker-compose.yml up -d
```

V2 continues using Flask and ignores the Django database. Keep the full data
backup so a later v3 upgrade can resume safely.

## Local development

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
mkdir -p data
export DATA_DIR="$PWD/data"
export SECRET_KEY="development-only-secret-that-is-long-enough"
export DJANGO_DEBUG=true
python manage.py migrate
START_MONITORING=1 python manage.py runserver --noreload 0.0.0.0:5000
```

## Tests

```sh
pytest -q
python manage.py check
python -m compileall -q manage.py config.py models.py lumentrace core services utils
```

The suite covers authentication and authorization, Flask-account migration,
application routes, settings persistence, atomic state storage, low-battery
recovery, and staggered multi-UPS recovery.

## Beta publishing

Every successful push to `beta/v3` publishes:

```text
pwsmith1988/lumentrace:v3
pwsmith1988/lumentrace:v3-beta
```

The workflow tests the Django application before building multi-platform images
with SBOM and provenance metadata. Stable `latest` and all v2 tags remain
unchanged.

See [BETA_NOTES_v3.md](BETA_NOTES_v3.md) for beta-specific upgrade and rollback
instructions and [SECURITY.md](SECURITY.md) for deployment guidance.

## Credits and license

LumenTrace was inspired by the original
[wolnut](https://github.com/hardwarehaven/wolnut) project.

The LumenTrace source is released under the [Unlicense](LICENSE). Bundled
third-party assets retain their original licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [LICENSES](LICENSES/).
