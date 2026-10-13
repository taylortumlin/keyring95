#!/usr/bin/env python3
"""KeyRing 95: find, rotate and age-track the API keys your self-hosted apps use.

One file, Python standard library only. Stores fingerprints and dates, never a key.

  python3 keyring95.py demo      try it: fake apps, no Proxmox needed, http://127.0.0.1:8099
  python3 keyring95.py passwd    set the login password
  python3 keyring95.py health    print the reminder status (same as GET /health)
  python3 keyring95.py           serve
"""
import base64, datetime as dt, getpass, hashlib, hmac, ipaddress, json, os, re, secrets
import shutil, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "0.2.1"
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.environ.get("KEYRING_CONFIG") or next(
    (p for p in ("/etc/keyring95/config.json", os.path.join(HERE, "config.json")) if os.path.exists(p)),
    "/etc/keyring95/config.json")
STATE_DIR = os.environ.get("KEYRING_STATE", "/var/lib/keyring95")
PORT = int(os.environ.get("KEYRING_PORT", "8099"))
DEFAULT_ALLOW = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "::1/128"]
LOCK = threading.Lock()
DEMO = False


# ---------- providers ----------
# A provider knows what its keys look like and how to prove a key works.
# Adding one = one entry here. See ROADMAP.md for the ones queued up.

def _http_ok(url, headers, also_ok=None):
    """One authenticated GET. also_ok: {status: (body substring, message)} for answers that
    still prove the key is real, e.g. a send-only key refused a read endpoint."""
    req = urllib.request.Request(url, headers={"User-Agent": f"keyring95/{__version__}", **headers})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200, "Key works"
    except urllib.error.HTTPError as e:
        body = e.read(2000).decode("utf-8", "replace")
        hint, msg = (also_ok or {}).get(e.code, (None, None))
        if hint is not None and hint in body:
            return True, msg
        return False, {400: "Provider rejected this key (400)", 401: "Provider rejected this key (401)",
                       403: "Key lacks permission (403)"}.get(e.code, f"HTTP {e.code}")
    except Exception as e:  # network trouble is not the key's fault; say so
        return False, f"Could not reach the provider: {e}"


def _bearer(url, **kw):
    return lambda k: _http_ok(url, {"Authorization": f"Bearer {k}"}, **kw)


# pattern: POSIX ERE, because discovery also feeds it to `grep -E`. Keep prefixes specific so the
#   scan doesn't flag random strings. scan=False for keys with no recognisable shape (rotate-only).
# display: how the provider's console abbreviates a key (prefix group + 3 chars, then …last4).
# example: placeholder for the paste box.
PROVIDERS = {
    "anthropic": {
        "name": "Anthropic (Claude)", "example": "sk-ant-api03-…",
        "pattern": r"sk-ant-api[0-9]*-[A-Za-z0-9_-]{20,}",
        "display": r"(sk-ant-api\d*-)(.{3})",  # mirrors the Console: sk-ant-api03-7gS…jgAA
        "test": lambda k: _http_ok("https://api.anthropic.com/v1/models?limit=1",
                                   {"x-api-key": k, "anthropic-version": "2023-06-01"}),
    },
    "openai": {
        "name": "OpenAI", "example": "sk-proj-…",
        "pattern": r"sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
        "display": r"(sk-(?:proj-|svcacct-|admin-)?)(.{3})",
        "test": _bearer("https://api.openai.com/v1/models"),
    },
    "google": {
        "name": "Google (Gemini)", "example": "AIza…",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "display": r"(AIza)(.{3})",
        "test": lambda k: _http_ok("https://generativelanguage.googleapis.com/v1beta/models?pageSize=1",
                                   {"x-goog-api-key": k}),
    },
    "groq": {
        "name": "Groq", "example": "gsk_…",
        "pattern": r"gsk_[A-Za-z0-9]{40,}",
        "display": r"(gsk_)(.{3})",
        "test": _bearer("https://api.groq.com/openai/v1/models"),
    },
    "xai": {
        "name": "xAI (Grok)", "example": "xai-…",
        "pattern": r"xai-[A-Za-z0-9]{40,}",
        "display": r"(xai-)(.{3})",
        "test": _bearer("https://api.x.ai/v1/models"),
    },
    "openrouter": {
        "name": "OpenRouter", "example": "sk-or-v1-…",
        "pattern": r"sk-or-v1-[a-f0-9]{64}",
        "display": r"(sk-or-v1-)(.{3})",
        "test": _bearer("https://openrouter.ai/api/v1/key"),  # /models is public; /key needs auth
    },
    "mistral": {
        "name": "Mistral", "example": "32 letters and digits", "scan": False,
        "pattern": r"[A-Za-z0-9]{32}",
        "test": _bearer("https://api.mistral.ai/v1/models"),
    },
    "huggingface": {
        "name": "Hugging Face", "example": "hf_…",
        "pattern": r"hf_[A-Za-z0-9]{30,}",
        "display": r"(hf_)(.{3})",
        "test": _bearer("https://huggingface.co/api/whoami-v2"),
    },
    "elevenlabs": {
        "name": "ElevenLabs", "example": "sk_…",
        "pattern": r"sk_[a-f0-9]{48}",
        "display": r"(sk_)(.{3})",
        "test": lambda k: _http_ok("https://api.elevenlabs.io/v1/user", {"xi-api-key": k},
                                   also_ok={401: ("missing_permissions", "Key works (scoped key)")}),
    },
    "resend": {
        "name": "Resend", "example": "re_…",
        "pattern": r"re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}",
        "display": r"(re_)(.{3})",
        "test": _bearer("https://api.resend.com/domains",
                        also_ok={401: ("restricted_api_key", "Key works (sending-only key)")}),
    },
    "sendgrid": {
        "name": "SendGrid", "example": "SG.…",
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "display": r"(SG\.)(.{3})",
        "test": _bearer("https://api.sendgrid.com/v3/scopes"),
    },
    "stripe": {
        "name": "Stripe", "example": "sk_live_… or rk_live_…",
        "pattern": r"(sk|rk)_(live|test)_[A-Za-z0-9]{20,}",
        "display": r"([sr]k_(?:live|test)_)(.{3})",
        "test": _bearer("https://api.stripe.com/v1/balance",
                        also_ok={403: ("", "Key works (restricted key)")}),
    },
    "github": {
        "name": "GitHub token", "example": "github_pat_… or ghp_…",
        "pattern": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}",
        "display": r"(ghp_|github_pat_)(.{3})",
        "test": _bearer("https://api.github.com/user"),
    },
}


def detect(key):
    """Which provider a pasted or found key belongs to, judged by its shape."""
    return next((pid for pid, p in PROVIDERS.items()
                 if p.get("scan", True) and re.fullmatch(p["pattern"], key)), None)


def shape_error(key, pid):
    """None if the key fits provider pid, else a message that names what it looks like instead."""
    if re.fullmatch(PROVIDERS[pid]["pattern"], key):
        return None
    a = lambda n: ("an " if n[0] in "AEIOU" else "a ") + n
    other = detect(key)
    if other:
        return f"That looks like {a(PROVIDERS[other]['name'])} key, but these apps use {PROVIDERS[pid]['name']}."
    return f"That doesn't look like {a(PROVIDERS[pid]['name'])} key."


def provider(app):
    return PROVIDERS[app.get("provider", "anthropic")]


def fingerprint(key, prov):
    m = re.match(prov.get("display", r"(.{6})()"), key)
    head = m.group(1) + m.group(2) if m else key[:8]
    return {"display": f"{head}…{key[-4:]}", "hash": hashlib.sha256(key.encode()).hexdigest()[:8]}


def test_key(key, prov):
    if isinstance(prov, str):  # a provider id: check the shape before calling anyone
        err = shape_error(key, prov)
        if err:
            return False, err
        prov = PROVIDERS[prov]
    if DEMO:
        ok = re.fullmatch(prov["pattern"], key) and "bad" not in key
        return bool(ok), "Key works (demo)" if ok else "Provider rejected this key (demo)"
    return prov["test"](key)


# ---------- runners ----------
# A runner executes a shell snippet where the app lives. Secrets go in via stdin, never argv.

def run(app, script, stdin=None, timeout=60):
    if DEMO:
        return demo_run(app, script, stdin)
    if "ct" in app:
        cmd = ["pct", "exec", str(app["ct"]), "--", "sh", "-c", script]
    else:
        raise ValueError(f"{app['id']}: no runner (set \"ct\" for a Proxmox container)")
    r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr.strip()


def list_hosts():
    """Every place `discover` should look. Proxmox: all running containers."""
    if DEMO:
        return [{"ct": a["ct"], "id": f"ct{a['ct']}"} for a in load_config()["apps"]]
    out = subprocess.run(["pct", "list"], capture_output=True, text=True).stdout.splitlines()[1:]
    return [{"ct": int(l.split()[0]), "id": f"ct{l.split()[0]}"} for l in out if " running " in l]


# ---------- demo mode ----------

DEMO_FILES = {}
DEMO_PROCS = []


def demo_key(pid, tag):
    h = hashlib.sha256(tag.encode()).hexdigest()
    if tag == "revoked":  # demo test_key rejects keys containing "bad"
        h = h[:6] + "bad" + h[9:]
    return {"anthropic": f"sk-ant-api03-{h[:40]}AA", "openai": f"sk-proj-{h[:48]}",
            "resend": f"re_{h[:8]}_{h[8:32]}", "groq": f"gsk_{h[:52]}", "github": f"ghp_{h[:36]}",
            "stripe": f"sk_live_{h[:32]}"}[pid]


def demo_config():
    apps = [("chatbot", 101, "/opt/chatbot/.env", "shared", "anthropic", "ANTHROPIC_API_KEY"),
            ("notes-ai", 102, "/var/lib/notes/.env", "shared", "anthropic", "ANTHROPIC_API_KEY"),
            ("recipe-scanner", 103, "/srv/recipes/.env", "recipes", "anthropic", "ANTHROPIC_API_KEY"),
            ("support-bot", 104, "/etc/support-bot/env", "revoked", "anthropic", "ANTHROPIC_API_KEY"),
            ("voice-agent", 106, "/opt/voice/.env", "voice", "openai", "OPENAI_API_KEY"),
            ("mailer", 107, "/opt/mailer/.env", "mail", "resend", "RESEND_API_KEY")]
    for _, ct, f, tag, pid, var in apps:
        DEMO_FILES[(ct, f)] = f"PORT=3000\n{var}={demo_key(pid, tag)}\n"
    # Keys no app is registered for, so the scan and Track have something to find.
    DEMO_FILES[(106, "/opt/voice/.env.bak-2026-03")] = f"OPENAI_API_KEY={demo_key('openai', 'old-voice')}\n"
    DEMO_FILES[(107, "/opt/shop/docker-compose.yml")] = (
        "services:\n  shop:\n    image: shop\n    environment:\n"
        f"      - STRIPE_SECRET_KEY={demo_key('stripe', 'shop')}\n")
    DEMO_FILES[(103, "/root/.config/gh/env")] = f"GH_TOKEN={demo_key('github', 'ci')}\n"
    DEMO_PROCS.append((101, "python", demo_key("groq", "stray")))
    return {"rotate_days": 90, "warn_days": 14,
            "apps": [{"id": i, "ct": ct, "file": f, "var": var, "provider": pid,
                      "reload": f"systemctl restart {i}", "check": f"systemctl is-active {i}"}
                     for i, ct, f, _, pid, var in apps],
            "manual": [{"id": "workflow-tool", "where": "Workflow tool UI → Credentials → paste → Save"},
                       {"id": "ci-secrets", "where": "GitHub → repo Settings → Secrets → ANTHROPIC_API_KEY"}]}


def demo_run(app, script, stdin):
    time.sleep(0.3)
    m = re.match(r"cat > '([^']+)'", script)
    if m:
        DEMO_FILES[(app["ct"], m.group(1))] = stdin
        return 0, "", ""
    m = re.match(r"cat '([^']+)'", script)
    if m:
        body = DEMO_FILES.get((app["ct"], m.group(1)))
        return (0, body, "") if body else (1, "", "No such file")
    if "/proc/" in script:
        apps = {(a["ct"], a["file"]) for a in load_config()["apps"]}
        hits = []
        for (ct, f), body in DEMO_FILES.items():
            if ct == app["ct"]:
                k = body.strip().splitlines()[-1].split("=", 1)[1]
                hits += [f"F {f} {k}"] + ([f"P node {k}"] if (ct, f) in apps else [])
        hits += [f"P {comm} {k}" for ct, comm, k in DEMO_PROCS if ct == app["ct"]]
        return 0, "\n".join(hits), ""
    m = re.match(r"f='([^']+)'", script)  # inspect_file
    if m:
        body = DEMO_FILES.get((app["ct"], m.group(1)))
        return (0, body + "##KR-COMPOSE\n", "") if body else (3, "", "No such file")
    return 0, "active", ""


# ---------- config + state ----------

def now():
    return dt.datetime.now().isoformat(timespec="seconds")


_demo_cfg = None


def load_config():
    global _demo_cfg
    if DEMO:
        _demo_cfg = _demo_cfg or demo_config()
        return _demo_cfg
    with open(CONFIG) as f:
        cfg = json.load(f)
    cfg.setdefault("rotate_days", 90)
    cfg.setdefault("warn_days", 14)
    cfg.setdefault("manual", [])
    return cfg


def save_config(cfg):
    """Track / Add app / Untrack write the config. The previous version is kept as config.json.prev."""
    global _demo_cfg
    if DEMO:
        _demo_cfg = cfg
        return
    tmp = CONFIG + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    shutil.copy2(CONFIG, CONFIG + ".prev")
    os.replace(tmp, CONFIG)


def state_path():
    return os.path.join(STATE_DIR, "state.json")


def load_state():
    try:
        with open(state_path()) as f:
            st = json.load(f)
    except FileNotFoundError:
        return {"apps": {}, "log": []}
    for meta in st["apps"].values():  # 0.0.0 called it console_name
        if "console_name" in meta:
            meta.setdefault("key_name", meta.pop("console_name"))
    return st


def save_state(st):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    tmp = state_path() + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(st, f, indent=1)
    os.replace(tmp, state_path())


def log(st, msg):
    st["log"].insert(0, {"t": now(), "msg": msg})
    del st["log"][300:]


def valid_date(d):
    if not d:
        return None
    dt.date.fromisoformat(d[:10])  # raises on junk
    return d[:10]


# ---------- core ----------

# A variable assignment as it appears in .env files, shell, systemd (Environment="VAR=…")
# and compose files (- VAR=… or VAR: …).
ASSIGN = r"^([ \t]*(?:-[ \t]*)?(?:export[ \t]+)?(?:Environment=[\"']?)?{var}[\"']?[ \t]*[=:][ \t]*[\"']?)"


def var_re(app):
    return ASSIGN.format(var=re.escape(app["var"])) + f"({provider(app)['pattern']})"


def read_key(app):
    """Return (full_key or None, file_text or None, error)."""
    try:
        rc, out, err = run(app, f"cat '{app['file']}'", timeout=20)
    except subprocess.TimeoutExpired:
        return None, None, "timed out reading file"
    if rc:
        return None, None, err or "cannot read file"
    m = re.search(var_re(app), out, re.M)
    return (m.group(2) if m else None), out, None


def age_status(meta, cfg):
    """Due = whichever comes first: the key's expiry, or rotated + rotate_days."""
    today = dt.date.today()
    rotated, expires = meta.get("rotated_at"), meta.get("expires_at")
    dues = []
    if rotated:
        dues.append(dt.date.fromisoformat(rotated[:10]) + dt.timedelta(days=cfg["rotate_days"]))
    if expires:
        dues.append(dt.date.fromisoformat(expires[:10]))
    out = {"age_days": (today - dt.date.fromisoformat(rotated[:10])).days if rotated else None,
           "due_date": min(dues).isoformat() if dues else None,
           "due_reason": "expires" if expires and min(dues) == dt.date.fromisoformat(expires[:10]) else "age"}
    if not dues:
        return {**out, "days_left": None, "status": "overdue"}
    left = (min(dues) - today).days
    out["days_left"] = left
    out["status"] = "overdue" if left <= 0 else "due-soon" if left <= cfg["warn_days"] else "ok"
    return out


def snapshot():
    cfg, st = load_config(), load_state()

    def common(app, meta):
        return {**age_status(meta, cfg), "key_name": meta.get("key_name"), "rotated_at": meta.get("rotated_at"),
                "expires_at": meta.get("expires_at"), "provider": provider(app)["name"],
                "provider_id": app.get("provider", "anthropic")}

    checks = st.get("checks", {})

    def one(app):
        key, _, err = read_key(app)
        c = common(app, st["apps"].get(app["id"], {}))
        fp = fingerprint(key, provider(app)) if key else None
        chk = checks.get(app["id"])
        dead = bool(fp and chk and chk["hash"] == fp["hash"] and chk["ok"] is False)
        return {**{k: app.get(k) for k in ("id", "ct", "file", "var", "note", "reload", "check")}, **c,
                "kind": "auto", "fp": fp, "checked": chk if chk and fp and chk["hash"] == fp["hash"] else None,
                "error": err or (None if key else "variable not found") or (chk["msg"] if dead else None),
                "status": "dead" if dead else c["status"] if key else "error"}

    with ThreadPoolExecutor(8) as ex:
        apps = list(ex.map(one, cfg["apps"]))
    apps += [{**m, **common(m, st["apps"].get(m["id"], {})), "kind": "manual"} for m in cfg["manual"]]
    shared = {}
    for a in apps:
        if a.get("fp"):
            shared.setdefault(a["fp"]["hash"], []).append(a["id"])
    for a in apps:
        a["shared_with"] = [x for x in shared.get(a["fp"]["hash"], []) if x != a["id"]] if a.get("fp") else []
    return {"apps": apps, "log": st["log"][:60], "rotate_days": cfg["rotate_days"], "warn_days": cfg["warn_days"],
            "version": __version__, "demo": DEMO, "can_edit": cfg.get("ui_can_edit", True),
            "last_check": st.get("last_check"),
            "providers": {pid: {"name": p["name"], "example": p["example"], "scan": p.get("scan", True)}
                          for pid, p in PROVIDERS.items()}}


def rotate(key, ids, key_name, expires_at=None):
    key = key.strip()
    cfg = load_config()
    apps = {a["id"]: a for a in cfg["apps"]}
    chosen = [apps[i] for i in ids if i in apps]
    if not chosen:
        return {"ok": False, "error": "Pick at least one app."}
    provs = {id(provider(a)): provider(a) for a in chosen}
    if len(provs) > 1:
        return {"ok": False, "error": "Those apps use different providers; rotate them separately."}
    prov = next(iter(provs.values()))
    pid = chosen[0].get("provider", "anthropic")
    err = shape_error(key, pid)
    if err:
        return {"ok": False, "error": err}
    ok, why = test_key(key, prov)
    if not ok:
        return {"ok": False, "error": why}
    expires_at = valid_date(expires_at)
    new_fp = fingerprint(key, prov)
    results, retired = [], set()
    with LOCK:
        st = load_state()
        for app in chosen:
            res = rotate_one(app, key)
            results.append({"id": app["id"], **res})
            if res["ok"]:
                if res["old_hash"] != new_fp["hash"]:
                    retired.add((res["old_hash"], res["old_display"]))
                st["apps"][app["id"]] = {"rotated_at": now(), "key_name": key_name or None, "fp": new_fp,
                                         "expires_at": expires_at}
                log(st, f"Rotated {app['id']} to {new_fp['display']}" + (f" ({key_name})" if key_name else "")
                    + (f", expires {expires_at}" if expires_at else ""))
            else:
                log(st, f"FAILED {app['id']}: {res['msg']}")
        save_state(st)
    # Old keys nobody uses any more are safe to delete at the provider.
    live = {a["fp"]["hash"] for a in snapshot()["apps"] if a.get("fp")}
    revoke = [d for h, d in retired if h not in live]
    return {"ok": all(r["ok"] for r in results), "results": results, "revoke": revoke, "fp": new_fp}


def rotate_one(app, key):
    old, text, err = read_key(app)
    if err:
        return {"ok": False, "msg": err}
    if not old:
        return {"ok": False, "msg": f"{app['var']} not found in {app['file']}"}
    if old == key:  # re-pasting the current key must not reset its rotation clock
        return {"ok": False, "msg": "already using this key; nothing changed"}
    new_text = re.sub(var_re(app), lambda m: m.group(1) + key, text, flags=re.M)

    def write(body):
        # `cat >` truncates in place: owner/group/mode survive; o-rwx tightens world-readable files.
        return run(app, f"cat > '{app['file']}' && chmod o-rwx '{app['file']}'", stdin=body)

    def reload_and_check():
        if not app.get("reload"):  # nothing to restart: the file is all there is
            return True, "written"
        rc, _, e = run(app, app["reload"], timeout=180)
        if rc:
            return False, f"reload failed: {e[-200:]}"
        time.sleep(0 if DEMO else 5)
        if not app.get("check"):
            return True, "reloaded"
        rc, out, e = run(app, app["check"], timeout=30)
        return rc == 0, (out.strip() or e or "check failed")

    rc, _, e = write(new_text)
    if rc:
        return {"ok": False, "msg": f"write failed: {e}"}
    ok, why = reload_and_check()
    if not ok:
        write(text)
        reload_and_check()
        return {"ok": False, "msg": f"{why}; rolled back to old key"}
    fp = fingerprint(old, provider(app))
    return {"ok": True, "msg": "rotated, reloaded, healthy" if app.get("check") else "rotated, reloaded" if app.get("reload") else "rotated (nothing to restart)", "old_hash": fp["hash"], "old_display": fp["display"]}


def edit(app_id, fields):
    """Set rotated date / expiry / key name by hand (manual apps, or correcting history)."""
    cfg = load_config()
    if app_id not in {a["id"] for a in cfg["apps"] + cfg["manual"]}:
        return {"ok": False, "error": "unknown app"}
    with LOCK:
        st = load_state()
        meta = st["apps"].setdefault(app_id, {})
        changes = []
        if "rotated_at" in fields:
            meta["rotated_at"] = valid_date(fields["rotated_at"]) or now()[:10]
            changes.append(f"rotated {meta['rotated_at'][:10]}")
        if "expires_at" in fields:
            meta["expires_at"] = valid_date(fields["expires_at"])
            changes.append(f"expires {meta['expires_at'] or 'never'}")
        if "key_name" in fields:
            meta["key_name"] = (fields["key_name"] or "").strip() or None
            changes.append(f"name {meta['key_name']}")
        log(st, f"Edited {app_id}: " + ", ".join(changes))
        save_state(st)
    return {"ok": True}


# Where scan looks on disk: env-ish files under the usual app homes. Apps that load .env
# themselves (dotenv) never show the key in /proc/*/environ, so processes alone miss them.
SCAN_DIRS = "/opt /srv /etc /var/lib /root /home /usr/local"
SCAN_NAMES = ("'.env*' '*.env' env 'docker-compose*.y*ml' 'compose*.y*ml' '*.service' "
              "'config.json' 'secrets*' '*.conf'")


def discover():
    """Scan every host for keys: live process environments plus env files on disk."""
    known = {}
    for a in snapshot()["apps"]:
        if a.get("fp"):
            known.setdefault(a["fp"]["hash"], []).append((a["id"], a.get("ct")))
    pattern = "|".join(f"({p['pattern']})" for p in PROVIDERS.values() if p.get("scan", True))
    names = " -o ".join(f"-name {n}" for n in SCAN_NAMES.split())
    script = (
        "{ for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); "
        "tr '\\0' '\\n' < $p/environ 2>/dev/null | grep -oE '" + pattern + "' | "
        "while read -r k; do echo \"P $c $k\"; done; done; "
        f"find {SCAN_DIRS} -maxdepth 4 \\( -name node_modules -o -name .git -o -name docker "
        f"-o -name containers -o -name lxcfs \\) -prune -o -type f \\( {names} \\) -size -512k -print0 "
        "2>/dev/null | xargs -0 -r grep -HoE '" + pattern + "' 2>/dev/null | "
        "while IFS= read -r l; do echo \"F ${l%:*} ${l##*:}\"; done; } | sort -u")

    def tracked_as(h, ct):  # prefer the apps in this container; a shared key is tracked elsewhere too
        apps = known.get(h, [])
        here = [i for i, c in apps if c == ct]
        return ", ".join(here or [i for i, _ in apps]) or None

    def scan(host):
        try:
            _, out, _ = run(host, script, timeout=90)
        except Exception:
            return []
        keys = {}  # one row per key per host, listing every place it turned up
        for line in out.splitlines():
            kind, rest = line[:1], line[2:]
            where, _, k = rest.rpartition(" ")
            pid = detect(k)
            if not pid:
                continue
            fp = fingerprint(k, PROVIDERS[pid])
            hit = keys.setdefault(fp["hash"], {"ct": host["ct"], "fp": fp, "provider": PROVIDERS[pid]["name"],
                                               "provider_id": pid, "known_as": tracked_as(fp["hash"], host["ct"]),
                                               "processes": [], "files": []})
            hit["processes" if kind == "P" else "files"].append(where)
        for h in keys.values():
            h["processes"] = sorted(set(h["processes"]))
            h["backup_only"] = not h["processes"] and all(
                re.search(r"\.(bak|orig|old)|backup|attic", f, re.I) for f in h["files"])
        return list(keys.values())

    hosts = list_hosts()
    with ThreadPoolExecutor(8) as ex:
        hits = [h for hs in ex.map(scan, hosts) for h in hs]
    hits.sort(key=lambda h: (h["known_as"] is not None, h["backup_only"], h["provider"], h["ct"]))
    return {"hits": hits, "scanned": len(hosts)}


# ---------- live checks: is each key still accepted? ----------

def verify():
    """Ask each provider whether each app's key still works. Catches keys revoked or expired early.
    Network trouble is recorded as unknown, never as dead."""
    cfg = load_config()

    def one(app):
        key, _, _ = read_key(app)
        if not key:
            return app["id"], None
        ok, msg = test_key(key, provider(app))
        if not ok and msg.startswith("Could not reach"):
            ok = None
        return app["id"], {"t": now(), "ok": ok, "msg": msg, "hash": fingerprint(key, provider(app))["hash"]}

    with ThreadPoolExecutor(8) as ex:
        res = {i: r for i, r in ex.map(one, cfg["apps"]) if r}
    dead = [i for i, r in res.items() if r["ok"] is False]
    unknown = [i for i, r in res.items() if r["ok"] is None]
    with LOCK:
        st = load_state()
        st.setdefault("checks", {}).update(res)
        st["last_check"] = now()
        if dead or unknown or not st["log"] or not st["log"][0]["msg"].startswith("Checked"):
            why = ", ".join(f"{i} ({res[i]['msg']})" for i in dead)
            log(st, f"Checked {len(res)} keys with their providers: " + (f"DEAD {why}" if dead else "all accepted")
                + (f"; could not reach provider for {', '.join(unknown)}" if unknown else ""))
        save_state(st)
    return {"results": res, "dead": dead, "unknown": unknown}


def check_loop(hours):
    time.sleep(90)  # let the host settle after a boot
    while True:
        try:
            verify()
        except Exception as e:
            print(f"key check failed: {e}", flush=True)
        time.sleep(hours * 3600)


# ---------- tracking: add keys from the UI instead of editing config.json ----------

ID_RE, VAR_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,40}", r"[A-Za-z_][A-Za-z0-9_]{0,80}"
PATH_RE = r"/[^'\0\n\r]{1,300}"
GENERIC_DIRS = {"opt", "etc", "srv", "root", "home", "lib", "var", "usr", "local", "config", ".config", "app", "data"}


def inspect_file(ct, path, want=None):
    """Look at a file in a container and suggest how to track it: which variable holds a key,
    which provider, and how the app picks up a new one. Returns no key material."""
    if not re.fullmatch(PATH_RE, path or ""):
        return {"ok": False, "error": "File must be an absolute path."}
    try:
        ct = int(ct)
    except (TypeError, ValueError):
        return {"ok": False, "error": "Container ID must be a number."}
    script = (f"f='{path}'; d=$(dirname \"$f\"); export HOME=${{HOME:-/root}}\n"
              "cat \"$f\" || exit 3\n"
              "echo '##KR-COMPOSE'; ls \"$d\"/docker-compose*.y*ml \"$d\"/compose*.y*ml 2>/dev/null\n"
              # units that mention the file (or run from its folder), with whether they're running now
              "echo '##KR-UNITS'; for u in $(grep -lsF -e \"$f\" -e \"WorkingDirectory=$d\""
              " /etc/systemd/system/*.service /etc/systemd/system/*.service.d/*.conf /lib/systemd/system/*.service"
              " 2>/dev/null); do n=$(basename \"$u\"); case \"$u\" in *.service.d/*) n=$(basename \"$(dirname \"$u\")\" .d);; esac;"
              " echo \"$n $(systemctl show -p ActiveState --value \"$n\" 2>/dev/null)\"; done\n"
              "echo '##KR-PM2'; command -v pm2 >/dev/null 2>&1 && pm2 jlist 2>/dev/null | tail -n 1\n")
    try:
        rc, out, err = run({"ct": ct, "id": f"ct{ct}"}, script, timeout=30)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Timed out reading the container."}
    if rc == 3 or "##KR-COMPOSE" not in out:
        return {"ok": False, "error": err or f"Can't read {path} in CT {ct}."}
    body, _, rest = out.partition("##KR-COMPOSE")
    sect = dict(re.findall(r"##KR-(\w+)\n?(.*?)(?=##KR-|\Z)", "##KR-COMPOSE" + rest, re.S))
    if DEMO:
        sect = {"COMPOSE": "", "UNITS": "", "PM2": ""}

    cands = []
    for m in re.finditer(ASSIGN.format(var=f"({VAR_NAME})") + r"([^\s\"'#]+)", body, re.M):
        var, val = m.group(2), m.group(3)
        pid = detect(val)
        if pid:
            fp = fingerprint(val, PROVIDERS[pid])
            cands.append({"var": var, "provider_id": pid, "provider": PROVIDERS[pid]["name"], "fp": fp})
    if not cands:
        return {"ok": False, "error": f"No key KeyRing recognises in {path}."}
    pick = next((c for c in cands if c["fp"]["hash"] == want), cands[0])

    d = os.path.dirname(path)
    name, reload_, check = None, "", ""
    # Every running unit that reads this file needs the restart (one-shots pick it up next run).
    units = [l.split() for l in sect.get("UNITS", "").splitlines() if l.strip()]
    running = sorted({u[0] for u in units if len(u) > 1 and u[1] in ("active", "activating", "reloading")})
    if re.match(r"/(etc|lib)/systemd/system/", path):
        unit = os.path.basename(os.path.dirname(path))[:-2] if path.endswith(".conf") else os.path.basename(path)
        name, reload_ = unit.removesuffix(".service"), f"systemctl daemon-reload && systemctl restart {unit}"
        check = f"systemctl is-active {unit}"
    elif running:
        name = min(running, key=len).removesuffix(".service")  # sprout.service over sprout-notify.service
        reload_, check = f"systemctl restart {' '.join(running)}", f"systemctl is-active {' '.join(running)}"
    elif sect.get("COMPOSE", "").strip() or re.search(r"compose[^/]*\.ya?ml$", path):
        name = os.path.basename(d)
        reload_ = f"cd {d} && docker compose up -d --force-recreate"
        check = f"cd {d} && test -n \"$(docker compose ps -q --status running)\""
    else:
        try:
            procs = json.loads(sect.get("PM2", "").strip() or "[]")
        except ValueError:
            procs = []
        # the pm2 app that mentions this file, else the one running from its folder, else the only one
        p = (next((p for p in procs if path in json.dumps(p.get("pm2_env") or {})), None)
             or next((p for p in procs if (p.get("pm2_env") or {}).get("pm_cwd", "").rstrip("/") == d), None)
             or (procs[0] if len(procs) == 1 else None))
        if p:
            name = p.get("name")
            reload_, check = f"pm2 restart {name} --update-env", f"pm2 describe {name} | grep -q online"
        procs = None  # holds other apps' env; drop it
    if not name:
        parts = [x for x in d.split("/") if x and x not in GENERIC_DIRS]
        name = parts[-1] if parts else f"ct{ct}"
    name = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-.") or f"ct{ct}"
    taken = {a["id"] for a in load_config()["apps"] + load_config()["manual"]}
    if name in taken:
        name = f"{name}-{pick['provider_id']}"
    return {"ok": True, "id": name, "ct": ct, "file": path, "var": pick["var"], "provider_id": pick["provider_id"],
            "reload": reload_, "check": check, "candidates": cands,
            "how": "found" if reload_ else "unknown"}


def track(b):
    """Add an app (KeyRing rotates it) or a by-hand entry, from the UI."""
    cfg = load_config()
    if not cfg.get("ui_can_edit", True):
        return {"ok": False, "error": "Editing from the UI is turned off (ui_can_edit: false). Edit config.json."}
    s = lambda k: str(b.get(k) or "").strip()
    app_id, pid, kind = s("id"), s("provider") or "anthropic", s("kind") or "auto"
    if not re.fullmatch(ID_RE, app_id):
        return {"ok": False, "error": "Name: letters, digits, dot, dash or underscore."}
    if app_id in {a["id"] for a in cfg["apps"] + cfg["manual"]}:
        return {"ok": False, "error": f"There's already an app called {app_id}."}
    if pid not in PROVIDERS:
        return {"ok": False, "error": "Unknown provider."}
    if kind == "manual":
        entry = {"id": app_id, "provider": pid, "where": s("where") or "Update by hand"}
    else:
        entry = {"id": app_id, "provider": pid, "ct": None, "file": s("file"), "var": s("var"),
                 "reload": s("reload"), "check": s("check")}
        try:
            entry["ct"] = int(s("ct"))
        except ValueError:
            return {"ok": False, "error": "Container ID must be a number."}
        if not re.fullmatch(PATH_RE, entry["file"]):
            return {"ok": False, "error": "File must be an absolute path."}
        if not re.fullmatch(VAR_NAME, entry["var"]):
            return {"ok": False, "error": "Variable: letters, digits and underscores."}
        if "\n" in entry["reload"] + entry["check"]:
            return {"ok": False, "error": "Reload and check are one line each."}
        if entry["check"] and not entry["reload"]:
            return {"ok": False, "error": "A check needs a reload to check."}
        for k in ("reload", "check"):  # blank = nothing to restart (e.g. a CLI token file)
            if not entry[k]:
                del entry[k]
        key, _, err = read_key(entry)
        if not key:
            return {"ok": False, "error": err or f"No {PROVIDERS[pid]['name']} key in {entry['var']} in {entry['file']}."}
    if s("note"):
        entry["note"] = s("note")
    with LOCK:
        cfg = load_config()
        cfg["manual" if kind == "manual" else "apps"].append(entry)
        save_config(cfg)
        st = load_state()
        meta = {"rotated_at": valid_date(s("rotated_at")), "expires_at": valid_date(s("expires_at")),
                "key_name": s("key_name") or None}
        if any(meta.values()):
            st["apps"][app_id] = meta
        log(st, f"Now tracking {app_id}" + (" (by hand)" if kind == "manual" else f": CT {entry['ct']} {entry['file']}"))
        save_state(st)
    return {"ok": True}


def untrack(app_id):
    cfg = load_config()
    if not cfg.get("ui_can_edit", True):
        return {"ok": False, "error": "Editing from the UI is turned off (ui_can_edit: false)."}
    with LOCK:
        cfg = load_config()
        before = len(cfg["apps"]) + len(cfg["manual"])
        cfg["apps"] = [a for a in cfg["apps"] if a["id"] != app_id]
        cfg["manual"] = [a for a in cfg["manual"] if a["id"] != app_id]
        if len(cfg["apps"]) + len(cfg["manual"]) == before:
            return {"ok": False, "error": "unknown app"}
        save_config(cfg)
        st = load_state()
        st["apps"].pop(app_id, None)
        st.get("checks", {}).pop(app_id, None)
        log(st, f"Stopped tracking {app_id} (the app and its key were not touched)")
        save_state(st)
    return {"ok": True}


def locate(key):
    """'I leaked a key': is it still live, and where does it live? Searches by fingerprint."""
    key = key.strip()
    pid = detect(key)
    if not pid:
        return {"ok": False, "error": "KeyRing doesn't recognise that kind of key."}
    prov = PROVIDERS[pid]
    fp = fingerprint(key, prov)
    live, live_msg = test_key(key, prov)
    snap = snapshot()
    tracked = [a["id"] for a in snap["apps"] if a.get("fp") and a["fp"]["hash"] == fp["hash"]]
    by_hand = [a["id"] for a in snap["apps"] if a["kind"] == "manual" and a["provider_id"] == pid]
    scan = discover()
    hits = [h for h in scan["hits"] if h["fp"]["hash"] == fp["hash"]]
    return {"ok": True, "fp": fp, "provider": prov["name"], "provider_id": pid, "live": live, "live_msg": live_msg,
            "tracked": tracked, "by_hand": by_hand, "hits": hits, "scanned": scan["scanned"]}


def health_text():
    snap = snapshot()
    by = lambda *s: [a["id"] for a in snap["apps"] if a["status"] in s]
    due, broken, dead = by("overdue", "due-soon"), by("error"), by("dead")
    if not due and not broken and not dead:
        return 200, "KEYS OK"
    parts = ([f"DEAD: {', '.join(dead)}"] if dead else []) + ([f"KEYS DUE: {', '.join(due)}"] if due else []) \
        + ([f"UNREADABLE: {', '.join(broken)}"] if broken else [])
    return 503, " | ".join(parts)


# ---------- auth + http ----------

def passwd_path():
    return os.path.join(STATE_DIR, "passwd")


def set_password():
    pw = getpass.getpass("New KeyRing 95 password: ")
    if pw != getpass.getpass("Again: ") or len(pw) < 8:
        sys.exit("Passwords differ or shorter than 8 chars.")
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(os.open(passwd_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write(salt.hex() + ":" + h.hex())
    print("Saved.")


def check_password(pw):
    try:
        salt, h = open(passwd_path()).read().strip().split(":")
    except FileNotFoundError:
        return False
    return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex(), h)


class Handler(BaseHTTPRequestHandler):
    server_version = "KeyRing95"
    allow = []

    def log_message(self, fmt, *args):  # keep logs quiet; request bodies may hold keys
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def gate(self, auth=True):
        ip = ipaddress.ip_address(self.client_address[0])
        if not any(ip.version == n.version and ip in n for n in self.allow):
            self.send(403, "forbidden", "text/plain"); return False
        if not auth or DEMO:
            return True
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
                if check_password(pw):
                    return True
            except Exception:
                pass
            time.sleep(1)
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="KeyRing 95"')
        self.end_headers()
        return False

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if 0 < n < 100_000 else {}

    def do_GET(self):
        if self.path == "/health":
            if self.gate(auth=False):
                code, text = health_text()
                self.send(code, text, "text/plain")
            return
        if not self.gate():
            return
        if self.path == "/":
            with open(os.path.join(HERE, "ui.html"), "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self.send(200, snapshot())
        else:
            self.send(404, {"error": "not found"})

    def do_POST(self):
        if not self.gate():
            return
        b = self.body()
        try:
            if self.path == "/api/test":
                key = b.get("key", "").strip()
                pid = b.get("provider") or detect(key) or "anthropic"
                self.send(200, {**dict(zip(("ok", "msg"), test_key(key, pid))), "provider": PROVIDERS[pid]["name"]})
            elif self.path == "/api/rotate":
                self.send(200, rotate(b.get("key", ""), b.get("apps", []), (b.get("key_name") or "").strip(),
                                      b.get("expires_at")))
            elif self.path == "/api/edit":
                self.send(200, edit(b.get("id"), {k: b[k] for k in ("rotated_at", "expires_at", "key_name") if k in b}))
            elif self.path == "/api/discover":
                self.send(200, discover())
            elif self.path == "/api/inspect":
                self.send(200, inspect_file(b.get("ct"), b.get("file"), b.get("hash")))
            elif self.path == "/api/track":
                self.send(200, track(b))
            elif self.path == "/api/untrack":
                self.send(200, untrack(b.get("id")))
            elif self.path == "/api/verify":
                self.send(200, verify())
            elif self.path == "/api/locate":
                self.send(200, locate(b.get("key", "")))
            else:
                self.send(404, {"error": "not found"})
        except Exception as e:
            self.send(500, {"ok": False, "error": str(e)})


def serve(bind):
    Handler.allow = [ipaddress.ip_network(n) for n in load_config().get("allow", DEFAULT_ALLOW)]
    hours = load_config().get("check_hours", 24)
    if hours and not DEMO:
        threading.Thread(target=check_loop, args=(hours,), daemon=True).start()
    print(f"KeyRing 95 v{__version__} on http://{bind}:{PORT}" + ("  (demo mode)" if DEMO else ""), flush=True)
    ThreadingHTTPServer((bind, PORT), Handler).serve_forever()


if __name__ == "__main__":
    cmd = sys.argv[1:2]
    if cmd == ["demo"]:
        DEMO = True
        STATE_DIR = tempfile.mkdtemp(prefix="keyring95-demo-")
        ago = lambda d: (dt.date.today() - dt.timedelta(days=d)).isoformat()
        ahead = lambda d: (dt.date.today() + dt.timedelta(days=d)).isoformat()
        save_state({"apps": {"recipe-scanner": {"rotated_at": ago(80), "key_name": "recipe-scanner"},
                             "support-bot": {"rotated_at": ago(5), "key_name": "support-bot", "expires_at": ahead(25)},
                             "workflow-tool": {"rotated_at": ago(120), "key_name": "workflow-tool"},
                             "ci-secrets": {"rotated_at": ago(12), "key_name": "github-actions"}},
                    "log": [{"t": now(), "msg": "Demo started. Try rotating chatbot + notes-ai off their shared key."}]})
        serve("127.0.0.1")
    elif cmd == ["passwd"]:
        set_password()
    elif cmd == ["health"]:
        print(health_text()[1])
    elif cmd in (["--version"], ["version"]):
        print(__version__)
    elif cmd:
        sys.exit(__doc__)
    else:
        if not os.path.exists(passwd_path()):
            sys.exit(f"No password set. Run: python3 {sys.argv[0]} passwd")
        if not os.path.exists(CONFIG):
            sys.exit(f"No config at {CONFIG}. Copy config.example.json there and edit it.")
        serve(os.environ.get("KEYRING_BIND", "0.0.0.0"))
