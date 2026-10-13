# Changelog

All notable changes to KeyRing 95. Versions follow [semver](https://semver.org), loosely, because we're very early.

## [0.2.2] - 2026-10-13

### Fixed
- **Track… could pick a dead copy.** With release folders (`releases/<date>/.env`), every old release holds the same key, and Track picked the first one listed, which nothing reads. The scan now records each process's working folder, and Track prefers the `.env` in the running app's folder (never a backup).
- **The scan skipped linked env files.** Release folders often link `.env` to one shared copy; the scan now follows links, and Track records the real file the link points to, so it survives the next deploy.
- pm2 restart detection also matches apps whose folder holds the link rather than the real file

## [0.2.1] - 2026-10-13

### Added
- **Column filters:** a filter row under the headers. Type to filter App, Key in use and Key name; pick from lists for CT, Provider, Rotated (last 30 days / over 90 days / never), Expires (within 30 days / has a date / never) and Status (needs attention, dead, overdue, by hand…). **Clear** resets them. Filters are remembered.
- **Sortable columns:** click a header to sort ascending, again for descending, a third time to turn it off. Status sorts by urgency.
- "Showing 6 of 14" when a filter is on. Select-all picks only the rows shown, and changing a filter unselects hidden rows, so you never rotate a row you can't see.

## [0.2.0] - 2026-10-13

*The one-stop shop release: find it, track it, check it, fix it.*

### Added
- **Track… from the scan.** Every untracked key gets a button. KeyRing reads the file, picks out the variable, and works out how the app restarts: systemd units (every running unit that reads the file), systemd drop-ins (with `daemon-reload`), docker compose, or pm2. Keys only found in a process environment become "update by hand" entries.
- **Tools ▸ Add app…** with a **Detect** button, for keys the scan can't see
- **Stop tracking…** in the Edit dialog
- **Live key checks:** once a day, and on **Tools ▸ Check every key now**, KeyRing asks each provider whether each key still works. Revoked or expired keys show as **Dead key** and `/health` reports `DEAD: …`. Set `check_hours` (default 24, 0 = off).
- **Tools ▸ I leaked a key…** Paste it: KeyRing says whether it still works, finds every app, file and process using it, offers **Track…** for untracked copies, selects the tracked apps for rotation and lists the steps
- Keys in systemd `Environment="VAR=…"` lines and compose `- VAR=…` / `VAR: …` entries can be rotated
- `reload` and `check` are optional, for files with nothing to restart (e.g. a CLI token)
- `ui_can_edit` (default on) lets the UI write `config.json`. The previous version is kept as `config.json.prev`.

### Changed
- Scan results name the app in each container rather than every app sharing the key

## [0.1.1] - 2026-10-13

### Changed
- The menu bar is a real menu bar now: File / Tools / Help open dropdowns. Click to open, hover to slide between menus, arrow keys and Enter to pick, Esc or click away to close, Alt+F/T/H from anywhere. F5 refreshes.

## [0.1.0] - 2026-10-12

*Same day. Turns out you have more than one kind of key.*

### Added
- **12 more providers:** OpenAI, Google (Gemini), Groq, xAI, OpenRouter, Mistral, Hugging Face, ElevenLabs, Resend, SendGrid, Stripe and GitHub tokens. Set `"provider"` per app.
- **Scan reads env files on disk too**, not just running processes. Apps that load `.env` with dotenv were invisible before.
- Scan results are grouped into **not tracked**, **only in backup copies** (old keys in `.bak` files) and **tracked**, and list every process and file each key turned up in
- **Test Key** works out the provider from the key itself, and says so when you paste the wrong kind ("That looks like a Groq key, but these apps use Anthropic")
- The paste box shows what the selected apps' keys look like
- **Help ▸ Supported keys**
- Demo mode has OpenAI and Resend apps, plus stray Groq, Stripe and GitHub keys and an old OpenAI key in a backup file

### Fixed
- Provider test calls send a `keyring95/<version>` User-Agent; some APIs refuse Python's default
- A key shared by two apps is reported as tracked by both, not just one

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

[0.2.2]: https://github.com/taylortumlin/keyring95/releases/tag/v0.2.2
[0.2.1]: https://github.com/taylortumlin/keyring95/releases/tag/v0.2.1
[0.2.0]: https://github.com/taylortumlin/keyring95/releases/tag/v0.2.0
[0.1.1]: https://github.com/taylortumlin/keyring95/releases/tag/v0.1.1
[0.1.0]: https://github.com/taylortumlin/keyring95/releases/tag/v0.1.0
[0.0.1]: https://github.com/taylortumlin/keyring95/releases/tag/v0.0.1
