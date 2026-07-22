# LumenTrace v2.0.0

LumenTrace v2.0.0 is a major modernization release focused on a clearer
interface, reliable outage recovery, and safer self-hosted operation.

## Highlights

- A redesigned, responsive monitoring interface
- Human-readable UPS and device status
- A persistent recovery state machine that survives restarts
- Correct recovery when batteries are still charging after utility power returns
- Correct recovery when multiple UPS systems return at different times
- Atomic state storage with a rolling backup
- On-demand network discovery and a unified device form
- Updated dependencies and a hardened multi-platform container

## Upgrade from an earlier release

Back up the current data directory:

```sh
cp -a ./data ./data-backup
```

Create `.env` from the supplied template and generate a new application secret:

```sh
cp .env.example .env
openssl rand -hex 48
```

Paste the generated value after `SECRET_KEY=`. Then update the container:

```sh
docker compose pull
docker compose up -d
```

Existing device and UPS settings are migrated automatically.

## Docker images

```text
pwsmith1988/lumentrace:2.0.0
pwsmith1988/lumentrace:2.0
pwsmith1988/lumentrace:latest
```

Images are intended for both `linux/amd64` and `linux/arm64`.

## Important security note

LumenTrace is intended for trusted local networks and does not include built-in
authentication. Do not expose port 5000 directly to the public internet. For
remote access, use an authenticated HTTPS reverse proxy and set
`SESSION_COOKIE_SECURE=true`.

## Validation

The release includes automated coverage for outage capture, recharge waiting,
multi-UPS recovery, Wake-on-LAN completion, atomic state storage, routes,
device creation, and settings persistence.

Thank you for using LumenTrace. Bug reports and contributions are welcome.
