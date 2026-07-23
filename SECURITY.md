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

LumenTrace provides built-in local administrator and viewer accounts. Passwords
are stored as scrypt hashes, and authentication data is kept in `/data/auth.db`.
Do not expose port 5000 directly to the public internet.

For remote access, place LumenTrace behind an HTTPS reverse proxy with an
an optional additional authentication layer such as Authelia, Authentik, or an
equivalent forward-auth service. Set `SESSION_COOKIE_SECURE=true` whenever the
application is accessed exclusively through HTTPS.

Keep `.env` private. In particular, never commit `SECRET_KEY` to source control.
Back up both `/data/state.json` and `/data/auth.db`. `AUTH_MODE=disabled` bypasses
all application authentication and should only be used temporarily on a trusted
network for emergency recovery.
