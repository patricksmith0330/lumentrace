# Changelog

All notable changes to LumenTrace are documented here. This project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- First-run local administrator setup
- Secure login and logout flow with scrypt password hashing
- Administrator and read-only viewer roles
- Local user administration and password reset tooling
- Security audit history for authentication and write operations
- Hardened session cookies, security headers, and session invalidation

### Changed

- All application pages and APIs now require authentication by default
- Existing `state.json` data remains separate from the new `auth.db` database
- Device controls and configuration actions are hidden from viewer accounts

## [2.0.1] - 2026-07-22

### Changed

- Replaced the original line mark with a clearer power-circuit logo
- Improved logo sizing in desktop and mobile navigation
- Added OCI metadata to published container images
- Added Docker build caching, SBOM generation, and provenance attestations
- Documented both automatic and direct multi-platform Docker Hub publishing

## [2.0.0] - 2026-07-22

### Added

- Responsive appliance-style dashboard and mobile navigation
- Persistent recovery states for outage capture, recharge waiting, and waking
- Multi-UPS recovery support
- On-demand network discovery
- Atomic state writes and rolling `state.json.bak` backup
- Thread-safe state access between requests and background monitoring
- Container health endpoint and Docker health check
- Automated application, storage, and recovery tests

### Changed

- Replaced technical UPS status codes with readable labels in the interface
- Unified the add and edit device forms
- Simplified settings and moved infrequent options into an Advanced section
- Updated Python dependencies and the Python 3.13 container base
- Reduced the container to the `NET_RAW` Linux capability
- Changed the public Compose configuration to use the published image

### Removed

- Draggable dashboard widgets and Sortable.js
- Battery chart dependency and oversized generated Tailwind bundle
- Legacy theme and density controls
- Duplicated inline page scripts and unused frontend styles

### Fixed

- Wake-on-LAN recovery being missed when power returned below the battery threshold
- Recovery being missed when multiple UPS systems returned online at different times
- Non-atomic state writes and shared mutable default state
- Ineffective per-route rate limiting
- Missing mobile navigation

### Upgrade notes

- `SECRET_KEY` is now required. Copy `.env.example` to `.env` and replace the
  placeholder with a long random value before starting the container.
- Existing `state.json` files are compatible. Back up the `data` directory
  before upgrading.
- The interface remains unauthenticated and should only be exposed through an
  authenticated reverse proxy when accessed outside a trusted LAN.
