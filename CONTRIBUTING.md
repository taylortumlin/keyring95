# Contributing

Thanks for wanting to help. Ground rules that keep KeyRing 95 what it is:

- **Standard library only.** No pip installs. It should run on a stock Proxmox host.
- **Two files.** `keyring95.py` and `ui.html`. Split them only if it clearly helps.
- **Never store or log a key.** Fingerprints only. Keys reach targets via stdin, never argv.
- **Keep the Win95 look.** Bevels are `.out` (raised) and `.in` (sunken).

## Run it

```sh
python3 keyring95.py demo     # http://127.0.0.1:8099, fake apps, no Proxmox
```

Every UI change can be tried in demo mode. If you add a runner or provider, make demo mode exercise it if you can.

## Adding a provider

Add an entry to `PROVIDERS` in `keyring95.py`:

```python
"groq": {
    "name": "Groq", "example": "gsk_…",
    "pattern": r"gsk_[A-Za-z0-9]{40,}",   # POSIX ERE: it's also passed to grep -E
    "display": r"(gsk_)(.{3})",           # how the provider's console abbreviates keys
    "test": _bearer("https://api.groq.com/openai/v1/models"),
},
```

- `pattern` must be POSIX ERE (no `\d`, `\w`); discovery hands it to `grep -E` inside containers.
- Keep the prefix specific: the scan greps every env file, and a loose pattern floods it with false hits. Keys with no telltale shape get `"scan": False` (rotate only).
- `test` must be **cheap and read-only**. Listing models is ideal. Never spend tokens. `also_ok` handles answers that still prove the key is real (e.g. a send-only key refused a read endpoint).
- Add a row to the README and tick the box in ROADMAP.md.

## Adding a runner

`run(app, script, stdin, timeout)` decides how to reach an app from its config fields. Today it handles `ct` (Proxmox). Add a branch (e.g. `host` → `ssh`) and extend `list_hosts()` so discovery can scan it.

## Pull requests

Small and focused, with a line in CHANGELOG.md under `Unreleased`. Say how you tested it: demo mode, a real host, or both.
