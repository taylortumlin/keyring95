# Security

KeyRing 95 runs as root on a hypervisor and handles API keys, so security reports are very welcome.

**Please don't open a public issue for a vulnerability.** Use GitHub's private reporting instead: the repo's **Security** tab → **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do. You'll get a reply within a week.

The design: no keys at rest, keys passed via stdin, Basic auth with PBKDF2, a client-network allow-list. The deployment assumption is a LAN or VPN, not the open internet. Reports that break those properties are the most valuable.
