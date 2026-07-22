# LumenTrace: Automated power recovery for your network.

 <img width="1440" height="807" alt="Screenshot 2025-07-31 at 5 34 14 PM (1)" src="https://github.com/user-attachments/assets/a4c0a0c9-6c1d-4efc-a498-9fb25ac1528a" />

# LumenTrace v2.0.0

LumenTrace v2.0.0 is a major modernization release focused on a simpler interface, safer outage recovery, and more reliable self-hosted operation.

## Highlights

### Redesigned interface

- New responsive, appliance-style dashboard
- Clear, human-readable UPS and device status
- Simplified navigation for desktop and mobile
- Unified device add and edit experience
- On-demand network discovery
- Streamlined settings with advanced options kept out of the way
- Removed draggable widgets, decorative effects, and unused frontend components

### More reliable power recovery

LumenTrace now uses a persistent recovery state machine.

When an outage occurs, it records which monitored devices were online. After utility power returns, LumenTrace continues checking every configured UPS until all units are online and have reached the configured battery threshold. It then sends Wake-on-LAN packets to the recorded devices.

This fixes cases where recovery could previously be missed when:

- Power returned before batteries reached the wake threshold
- Multiple UPS units recovered at different times
- The application or host restarted during recovery

### Safer state storage

- Atomic state-file updates
- Automatic `state.json.bak` backup
- Thread-safe access between the web application and background monitor
- Existing LumenTrace state remains compatible
- Recovery progress is preserved across restarts

### Security and deployment

- `SECRET_KEY` is now required
- Improved CSRF protection and request rate limiting
- Secure cookie configuration for HTTPS deployments
- Reduced Docker capabilities
- Read-only container filesystem
- Container health check
- Updated Python runtime and dependencies
- Multi-platform Docker images for AMD64 and ARM64

## Upgrade notes

Before upgrading, back up your existing data directory:

```bash
cp -a ./data ./data-backup
```

Create or update `.env`:

```dotenv
SECRET_KEY=replace-with-a-long-random-value
TZ=America/New_York
POLL_INTERVAL=10
```

Generate a secret with:

```bash
openssl rand -hex 48
```

If LumenTrace is accessed through HTTPS, also add:

```dotenv
SESSION_COOKIE_SECURE=true
```

Pull and start the new image:

```bash
docker compose pull
docker compose up -d
```

Your existing devices, UPS configurations, logs, and recovery data will be loaded automatically.

## Docker images

```text
pwsmith1988/lumentrace:2.0.0
pwsmith1988/lumentrace:2.0
pwsmith1988/lumentrace:latest
```

Example:

```yaml
services:
  lumentrace:
    image: pwsmith1988/lumentrace:2.0.0
    container_name: lumentrace
    restart: unless-stopped
    env_file: .env
    environment:
      TZ: ${TZ:-America/New_York}
      DATA_DIR: /data
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
    network_mode: host
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - ./data:/data
```

## Important security note

LumenTrace is intended for trusted local networks and does not include built-in user authentication.

If it is accessible outside your trusted LAN, place it behind an authenticated HTTPS reverse proxy such as Traefik with Basic Auth, Authelia, Authentik, or another forward-auth provider.

## Validation

This release includes automated coverage for:

- Outage detection and device snapshots
- Waiting for UPS batteries to recharge
- Multi-UPS recovery
- Wake-on-LAN recovery completion
- Atomic state storage and backups
- Primary application routes
- Device creation
- Settings validation and persistence

## Thank you

LumenTrace was inspired by the original `wolnut` project. Feedback, bug reports, and contributions are welcome.
