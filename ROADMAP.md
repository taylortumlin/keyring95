# Roadmap

KeyRing 95 started as "rotate my Claude keys across my Proxmox containers". The goal is **every API key your self-hosted stuff uses, wherever it lives**. Three parts grow independently:

- **Providers**: what a key looks like and how to prove it works
- **Runners**: where the app lives and how to reach it
- **Sinks**: the places a key has to be pasted that aren't a file (today these are "update by hand")

## 0.1: More providers

Each provider is one entry in `PROVIDERS`: a key pattern, a fingerprint shape, and one cheap authenticated test call.

- [ ] OpenAI (`sk-proj-…`, `GET /v1/models`)
- [ ] Google Gemini (`AIza…`)
- [ ] Mistral, Groq, xAI, OpenRouter, Together, DeepSeek
- [ ] ElevenLabs, Deepgram, AssemblyAI
- [ ] Resend, Postmark, SendGrid
- [ ] Twilio (SID + token pair: needs two-variable support)
- [ ] Stripe (restricted keys)
- [ ] Cloudflare API tokens (they expose their own expiry via `/user/tokens/verify`)
- [ ] GitHub fine-grained PATs (expiry readable from the API)
- [ ] Generic provider: any regex, test command optional

## 0.2: More places to run

- [ ] **SSH runner:** plain Linux hosts and VMs (`"host": "user@box"`)
- [ ] **Local runner:** the machine KeyRing runs on
- [ ] **Docker runner:** containers on a Docker host without Proxmox
- [ ] Docker image for KeyRing itself (for non-Proxmox setups)
- [ ] Kubernetes Secrets
- [ ] Discovery that suggests config: "Scan" → **Add to config** button

## 0.3: Automate the "update by hand" list

- [ ] GitHub Actions secrets (API, sealed-box encrypted)
- [ ] n8n credentials (public API)
- [ ] Vercel / Netlify / Cloudflare Workers environment variables
- [ ] Doppler / Infisical / Vaultwarden as a source of truth

## 0.4: Reminders that find you

- [ ] Webhook / ntfy / Discord / email when a key enters the warning window
- [ ] Calendar feed (`.ics`) of upcoming rotations
- [ ] Prometheus `/metrics` (days left per key)

## Later: talk to provider admin APIs

- [ ] Anthropic Admin API: read real key names and status, archive the old key after rotation so "delete it in the Console" goes away
- [ ] Same for providers that let you mint keys by API: full one-click rotation, no pasting
- [ ] Usage per key, to spot keys nobody uses

## Not planned

- Storing keys. KeyRing deliberately keeps only fingerprints. If you want a vault, use a vault; KeyRing could read from one (0.3).
- Multi-tenant SaaS.

Want one of these sooner? Open an issue, or better, a PR. Providers are the easiest place to start.
