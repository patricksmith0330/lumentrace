# LumenTrace v2.0.1

LumenTrace v2.0.1 is a small visual and container-publishing update to the
v2.0 release.

## Highlights

- A new power-circuit logo that remains clear at browser-icon and mobile sizes
- Improved logo proportions in the application header
- Docker images labeled with version, source, revision, license, and project links
- Multi-platform images for `linux/amd64` and `linux/arm64`
- SBOM and build-provenance attestations on automated releases

## Docker images

```text
pwsmith1988/lumentrace:2.0.1
pwsmith1988/lumentrace:2.0
pwsmith1988/lumentrace:latest
```

## Upgrade

```sh
docker compose pull
docker compose up -d
docker compose logs --tail 100 lumentrace
```

This release does not change the stored data format or configuration. Existing
v2.0.0 installations can be upgraded without migration.

## Security reminder

LumenTrace is designed for trusted local networks and does not provide built-in
authentication. Do not expose port 5000 directly to the public internet. Use an
authenticated HTTPS reverse proxy for remote access.
