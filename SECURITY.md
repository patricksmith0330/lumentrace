# Security Policy

## Supported versions

Security fixes are provided for the latest published LumenTrace release.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting feature on this repository, or contact the
maintainer privately if private reporting is unavailable.

Include the affected version, deployment configuration, reproduction steps,
and potential impact. Please allow reasonable time for investigation before
public disclosure.

## Deployment scope

LumenTrace is intended for a trusted local network. It does not provide user
accounts or built-in authentication. Do not expose port 5000 directly to the
public internet.

For remote access, place LumenTrace behind an HTTPS reverse proxy with an
authentication layer such as Traefik Basic Auth, Authelia, Authentik, or an
equivalent forward-auth service. Set `SESSION_COOKIE_SECURE=true` whenever the
application is accessed exclusively through HTTPS.

Keep `.env` private. In particular, never commit `SECRET_KEY` to source control.
