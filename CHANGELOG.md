# Changelog

All notable changes to KeyRing 95. Versions follow [semver](https://semver.org), loosely, because we're very early.

## [0.0.1] - 2026-10-12

*A.k.a. v.000000000001. The "it works on my homelab" release.*

### Added
- Reads each app's key over `pct exec` and shows its fingerprint in the same format as the provider's console
- Flags keys shared between apps
- Rotation: tests the key with the provider, rewrites the env file in place (keeps owner and mode, strips world-read), reloads, health-checks, and **rolls back automatically** if the app doesn't come back
- After a rotation, lists old keys no app uses any more, so you know what to delete
- Expiry tracking: a key is due at its expiry or `rotate_days` after rotation, whichever comes first
- `GET /health` for uptime monitors (`200 KEYS OK` / `503 KEYS DUE: …`)
- "Update by hand" entries for keys KeyRing can't reach (n8n, CI secrets, laptops), with **Mark done**
- **Scan for stray keys:** finds keys in running containers' process environments that no app is registered for
- Pasting the key an app already has is refused, so it can't reset the rotation clock
- `demo` mode: fake apps, no Proxmox, try it in 10 seconds
- Provider registry (Anthropic for now) and runner abstraction (Proxmox `pct` for now), ready for the [roadmap](ROADMAP.md)
- Windows 95 UI, because why not
- HTTP Basic auth (PBKDF2), client network allow-list, no keys at rest, no request logging
- `install.sh` for Proxmox VE hosts

[0.0.1]: https://github.com/taylortumlin/keyring95/releases/tag/v0.0.1
