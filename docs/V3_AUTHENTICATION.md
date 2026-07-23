# LumenTrace v3 authentication

## Scope

The v3 authentication foundation provides:

- first-run administrator setup
- local administrator and viewer accounts
- scrypt password hashing with unique salts
- signed, HTTP-only, SameSite session cookies
- session invalidation after password reset or account disablement
- CSRF protection on forms and API writes
- login throttling
- account and application-write audit events
- CLI account creation and password recovery

Authentication is enabled by default with `AUTH_MODE=local`. The health endpoint
at `/api/health` remains public for container orchestration. Every other page and
API requires a valid session.

## Roles

Administrators can manage devices, UPS connections, settings, and local users.
Viewers can open monitoring pages and read status APIs, but server-side checks
deny all state-changing requests.

## First-run and upgrades

When no local users exist, every browser page redirects to `/setup`. The first
account is always an administrator. Authentication uses `/data/auth.db` and does
not change existing `/data/state.json` device or UPS configuration.

## Recovery commands

List users:

```sh
docker compose exec lumentrace flask --app main auth list-users
```

Create an additional account:

```sh
docker compose exec lumentrace flask --app main auth create-user
```

Reset a password:

```sh
docker compose exec lumentrace flask --app main auth reset-password USERNAME
```

As a last-resort recovery measure on a trusted network, set
`AUTH_MODE=disabled`, restart the container, correct the account issue, and
restore `AUTH_MODE=local` immediately.

## Deployment requirements

- Keep `SECRET_KEY` stable and private. Replacing it signs every user out.
- Set `SESSION_COOKIE_SECURE=true` after HTTPS is working.
- Back up `auth.db` together with `state.json`.
- Keep LumenTrace behind an HTTPS reverse proxy for remote access.
- Do not share the same administrator account between people; create individual
  accounts so audit records remain attributable.
