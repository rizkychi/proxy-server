# proxy-server

A small, dependency-free HTTP proxy server in Python (asyncio, standard library only).

- **Forward proxy** — plain HTTP forwarding plus `CONNECT` tunnels for HTTPS. TLS passes through encrypted; the proxy never decrypts it.
- **Reverse proxy** — forward all traffic to a single upstream (useful in front of your own app / localhost service).
- **Metadata logging only** — method, host, status, byte count, duration. No headers or bodies are logged.
- **Optional Basic auth**, health endpoint, Docker support, no third-party dependencies.
- **New in 0.3.0:** live web dashboard at `/__dashboard` with a Lumi watchlist view (metadata only). **0.2.0:** response caching, per-IP rate limiting, host block/allowlist, `/__stats` dashboard data, JSON + file logging, and JSON config files.

> Use it on networks and systems you own or are authorized to test. This is a generic proxy — it does not inspect, decrypt, or modify TLS traffic or third-party application protocols.

## Quick start

```bash
# no install needed to run from source
PYTHONPATH=src python -m proxy_server --host 127.0.0.1 --port 8080

# or install it
pip install -e .
proxy-server --port 8080
```

Use it:

```bash
curl -x http://127.0.0.1:8080 http://example.com/
curl -x http://127.0.0.1:8080 https://example.com/   # via CONNECT tunnel
curl http://127.0.0.1:8080/__health
```

Reverse mode (proxy your own app on port 9000):

```bash
proxy-server --mode reverse --upstream http://127.0.0.1:9000 --port 8080
curl http://127.0.0.1:8080/
```

With auth:

```bash
PROXY_AUTH='user:secret' proxy-server --port 8080
curl -x http://user:secret@127.0.0.1:8080 http://example.com/
```

## Configuration

| CLI flag | Env var | Default | Description |
|---|---|---|---|
| `--host` | `PROXY_HOST` | `127.0.0.1` | Bind address (use `0.0.0.0` carefully) |
| `--port` | `PROXY_PORT` | `8080` | Listen port |
| `--mode` | `PROXY_MODE` | `forward` | `forward` or `reverse` |
| `--upstream` | `PROXY_UPSTREAM` | — | Upstream URL, required in reverse mode |
| `--auth` | `PROXY_AUTH` | — | `user:password` for Basic auth |
| `--timeout` | — | `30` | Upstream timeout (seconds) |

## New features (0.2.0)

```bash
# Cache GET responses for 60s, max 120 req/min per IP, block ad/tracker hosts
proxy-server --cache-ttl 60 --rate-limit 120 \
  --block '*.ads.example' --block tracker.example \
  --log-format json --log-file proxy.log

# Or load the same settings from a file (see config.example.json)
proxy-server --config config.example.json

# Live stats: requests, errors, bytes, cache hits, top hosts, by status
curl http://127.0.0.1:8080/__stats
```

| Flag | Default | Description |
|---|---|---|
| `--cache-ttl` | `0` (off) | Cache GET 200 responses for N seconds (max 1 MB each, 128 entries) |
| `--rate-limit` | `0` (off) | Max requests/minute per client IP, then `429` (health/stats exempt) |
| `--block` | — | Blocked host pattern, repeatable: `example.com` or `*.example.com` |
| `--allow` | — | If set, only matching hosts are allowed (`403` otherwise) |
| `--log-file` / `--log-format` | — / `text` | Append logs to a file; `text` or `json` lines |
| `--config` | — | JSON config file (CLI flags win over file values) |

## Dashboard + Lumi watch (0.3.0)

```bash
proxy-server --lumi --port 8080
# open in a browser:
#   http://127.0.0.1:8080/__dashboard
```

The dashboard auto-refreshes every 2 seconds and shows: request / error /
byte counters, cache and rate-limit counters, top hosts, and the last 50
connections through the proxy — time, method, host, status, bytes, duration.

With `--lumi` (or repeatable `--watch HOST` patterns of your own), connections
to Lumi Master / Bilibili endpoints are highlighted in a separate panel.
The preset covers the version/config and log endpoints found in the client,
e.g. `lumigo-cn-prod-vs.bilibiligame.net`, `lumigo-sg-prod-vs.bilibiligame.net`,
`lumigo-cn-prod-log.bilibiligame.net`, plus `*.bilibiligame.net` / `*.bilibili.com`.

**Scope: metadata only.** The dashboard records which host was contacted,
when, the status, and how many bytes moved. It does not read, decrypt, or
modify packet payloads, and the game's gateway traffic (delivered dynamically
via `VersionInfo.serverList`, on a custom TCP/WebSocket protocol) is not
HTTP — it will only appear here if it is routed through this proxy as a
CONNECT tunnel, and then only as host + byte counts.

### Payload viewer for your own server (0.4.0)

All settings live in the environment — copy `.env.example` to `.env`
(git-ignored, auto-loaded at startup) and fill in your own server's values:

```bash
PAYLOAD_CAPTURE=1
PAYLOAD_ALLOW_HOSTS=127.0.0.1,localhost   # only these hosts are ever captured
PAYLOAD_MAX_BYTES=4096
# optional, if YOUR server AES-128-CBC-encrypts bodies (needs `pip install cryptography`):
PAYLOAD_AES_KEY=<your 32-hex-char key>
PAYLOAD_AES_IV=<your 32-hex-char iv>
```

Then click a connection in the dashboard: the detail panel shows the
request and response bodies (text when printable, hex otherwise, truncated
at `PAYLOAD_MAX_BYTES`), plus a decrypted preview when key/IV are set.

#### LGEB-format bundles from your own server A (0.5.0)

If server A serves bundles in the LGEB container format — `b"LGEB"` +
`resVersion` (u32 LE) + AES-128-CBC/PKCS#7 ciphertext, with key/IV derived
as `SHA-256(salt + f"{contentHash}:{resVersion}")` split 16/16, and the
`contentHash` carried as the 32-hex suffix of the bundle file name — proxy
B can read them with the same derivation structure:

```bash
PAYLOAD_LGEB=1
PAYLOAD_LGEB_SALT_HEX=<server A's salt, 32 hex chars>
# PAYLOAD_LGEB_CONTENT_HASH=<override, if the file name carries no hash>
```

The salt is **not** built into the proxy: B derives nothing without A's
salt in its env. That is deliberate — a zero-config reader that needs
nothing from A would only be possible by embedding one specific
third-party system's fixed salt, which this project does not do. The
allowlist and the Bilibili hard-disable above apply to LGEB reading
exactly as they do to plain payload capture.

#### Intercept — hold / release / drop, both directions (0.6.0)

```bash
INTERCEPT=1
INTERCEPT_ALLOW_HOSTS=127.0.0.1,localhost
INTERCEPT_TIMEOUT=30   # seconds a held item waits, then it forwards
```

With intercept on, traffic to an allowlisted own host is parked twice:
once on the way out (**request / transfer**, before it reaches your
server) and once on the way back (**response / receive**, buffered in
full before it reaches the client). Held items appear in the dashboard's
Intercept panel with their body preview and **Release** / **Drop**
buttons; the same actions are available as
`GET /__intercept/release?id=N` and `GET /__intercept/drop?id=N`, and
`GET /__intercepts` lists what is currently held. Dropping a request
answers the client `403`; dropping a response answers `502`.

Scope notes: intercept is off by default, only ever applies to hosts in
`INTERCEPT_ALLOW_HOSTS`, is hard-disabled for the same Bilibili domains
as payload capture, and applies to plain-HTTP forward/reverse traffic —
`CONNECT` tunnels pass through raw and are not held.

#### Interactive dashboard settings (0.7.0)

Yes — env can be changed from the dashboard. The **Settings** panel at
`/__dashboard` is backed by `GET /__config` (current effective values)
and `POST /__config` (apply). Behaviour:

- Runtime settings (payload capture + allowlist, LGEB on/off, intercept
  on/off + allowlist + timeout, cache TTL, rate limit, log format) apply
  **live**, no restart.
- With *also save to .env* ticked (the default), the same values are
  merged into your `.env` so they survive a restart. Unticked, changes
  are live-only.
- Secrets (`PAYLOAD_LGEB_SALT_HEX`, `PAYLOAD_AES_KEY`, `PAYLOAD_AES_IV`)
  are **set-only**: the dashboard shows whether one is set, never its
  value, and leaving the field blank keeps the current secret.
- Bind settings (`PROXY_HOST` / `PROXY_PORT` / `PROXY_MODE` /
  `PROXY_UPSTREAM`) cannot move a listening socket, so they are saved
  to `.env` and reported as restart-required.

#### Phone clients on a public VPS (0.8.0)

B is an HTTP proxy, not a DNS server and not a VPN, so a phone connects
like this:

- **Wi-Fi, simplest:** in the Wi-Fi network's proxy settings choose
  *Manual* and enter B's public DNS/IP + port — or choose *Auto* and
  enter the PAC URL below.
- **PAC (recommended):** `GET /proxy.pac` returns a Proxy Auto-Config
  file. Hosts in `PAC_HOSTS` are routed `PROXY <PROXY_PUBLIC_HOST>`,
  everything else goes `DIRECT`, so only traffic for your server A
  passes through B. If `PAC_HOSTS` is empty it falls back to
  `PAYLOAD_ALLOW_HOSTS` / `INTERCEPT_ALLOW_HOSTS`; if those are empty
  too, everything is routed via B.
- **Mobile data / all apps, all networks:** Wi-Fi proxy settings do not
  apply. Use a VPN — either a VPN app on the phone that forwards to an
  HTTP proxy, or a tunnel (e.g. WireGuard) to the VPS with the proxy
  settings applied inside it. A custom *DNS* setting alone cannot do
  this: DNS only resolves names, it never forwards traffic.
- **If the port is public, set `PROXY_AUTH`** — an unauthenticated open
  proxy on the internet will be found and abused by strangers.

Guards, by design:

- Capture is **off by default** and only ever runs for hosts explicitly
  listed in `PAYLOAD_ALLOW_HOSTS`.
- Capture is **hard-disabled for `*.bilibili.com`, `*.bilibiligame.net`,
  and `*.bilibili.tv`** regardless of the allowlist — this feature is for
  debugging your own servers (e.g. one using the same protocol style on
  your own DNS/IP), not Bilibili's live endpoints.
- Keys/IVs are read from the environment only, never logged or stored.

#### HTTPS MITM + dashboard rebuild (0.9.0)

CONNECT tunnels are normally blind: B sees the host and byte counts,
never the content. With MITM on, B **terminates TLS** for hosts in
`MITM_ALLOW_HOSTS` (your own servers only — the same hard-disable for
Bilibili domains applies here too):

- B generates a local CA once into `MITM_CA_DIR` (default `.proxy-ca/`,
  git-ignored; the private key is stored `0600` and never served).
- Download the CA certificate from the dashboard's **HTTPS (MITM)**
  panel or `GET /__ca`, and install it as a trusted CA on your phone
  (Android: Settings → Security → Install a certificate → CA
  certificate; iPhone: install the profile, then enable full trust in
  Certificate Trust Settings). The panel shows the CA's SHA-256
  fingerprint so you can compare it on the phone.
- For each allowlisted host, B mints a leaf certificate from that CA,
  decrypts the phone ↔ B leg, and opens a second TLS leg to A using
  A's real certificate (`MITM_VERIFY_UPSTREAM=0` only if A is
  self-signed). Decrypted requests then flow through the normal path:
  payload capture, the LGEB reader, and intercept all work on HTTPS
  exactly as on plain HTTP.
- Apps with certificate pinning will still refuse the leaf cert; that
  can only be changed in the app itself.
- Requires `pip install cryptography`. Without it, MITM stays off and
  the dashboard panel says so.
- Toggle it live from the dashboard Settings (group "HTTPS (MITM)").

The dashboard was also rebuilt for readability: Indonesian labels with
a one-line explanation under every setting, formatted sizes/durations
(KB, ms, uptime), status pills, a search box + quick filters (Semua /
Dipantau / Error saja / CONNECT) for recent traffic, keyboard-operable
rows (Enter opens detail, Esc closes), an offline banner when the
server stops answering, a copyable PAC URL, and plain-language panels
for intercept ("Ditahan"), the watchlist, and MITM setup.

In 0.9.1 the dashboard layout became a multi-view admin UI with five
hash-routed views (`#/lalu-lintas`, …) so a refresh keeps your place:
**Ringkasan**, **Lalu lintas**, **Ditahan**, **HTTPS**, **Pengaturan**.

In 0.9.2 the dashboard was redesigned under the direction recorded in
`DESIGN.md` (an operations logbook: warm paper, ink, ruled sections).
Totals are a ledger strip instead of KPI cards, navigation is a
numbered text rail on desktop and a fixed bottom tab bar on phones,
status is colored text with a square swatch instead of pill badges,
and there are no icons, shadows, or gradients. All text meets WCAG AA
contrast on the paper background.

In 0.9.3 the dashboard was rebuilt again, this time on a design
system generated with the UI/UX Pro Max skill and persisted in
`design-system/proxy-server/` (MASTER.md, a dashboard page override,
and token files). The system is a dark slate console (background
`#0F172A`, cards `#1B2336`, accent green `#22C55E`) with Fira Sans
body text, Fira Code headings and data, and a dense 2/4/8/12/16/24/32
spacing scale. `DESIGN.md` records the fit checks: the generated
landing-page pattern and glassmorphism style were adapted to solid
surfaces for a live data console, while palette, typography, and
density are applied as generated. All text meets WCAG AA contrast.

In 0.9.4 the dashboard shell became a conventional admin layout:
a grouped sidebar (Menu utama / Konfigurasi / Sistem) that collapses
to icons on desktop and slides in as a drawer on phones, a sticky
topbar with breadcrumb, global traffic search, live status, and a
user menu, quick-action cards on the Dashboard view, and a profile
card with sign-out in the sidebar. It also gained a real dashboard
login: set `DASHBOARD_AUTH=user:password` in `.env` (separate from
`PROXY_AUTH`) and `/__dashboard` plus its admin APIs (stats, config,
intercepts, CA download) require a session from `/__login`; sign out
from the user menu or the sidebar profile card. Sessions are held in
memory with an HttpOnly cookie (`DASHBOARD_SESSION_TTL`, default
43200 seconds), so a restart signs everyone out. Without
`DASHBOARD_AUTH` the dashboard stays open and the user menu shows
how to enable login.

Version 0.9.5 replaced the visual design entirely: a light, modern
admin theme (soft gray background, white surfaces, indigo accent,
Plus Jakarta Sans for UI text and IBM Plex Mono for data), recorded
in `DESIGN.md`. Interaction was rebuilt around it: connection
details open in a right-hand slide-over drawer (click a row to show
or hide it, the row stays highlighted), destructive intercept drops
ask for confirmation in a modal dialog with proper focus handling,
payload previews can be opened full-size in a modal, and actions
report back through toast notifications. Success toasts dismiss
themselves; errors stay in a persistent alert with a retry button
until the connection recovers.

### Connection detail (0.3.1)

Click any row in **Recent traffic** to open its detail panel: connection id,
time, client peer, method, host, target/path, status, byte count, duration,
and whether it matched the Lumi watchlist. Payload contents are not captured,
stored, or shown — detail is metadata only.

## Docker

```bash
docker build -t proxy-server .
docker run --rm -p 8080:8080 proxy-server
```

## Development

```bash
pip install -e .
python -m pytest tests/ -q
```

## Project layout

```
src/proxy_server/
  server.py     # proxy implementation (forward, CONNECT, reverse)
  __main__.py   # python -m proxy_server
tests/
  test_proxy.py # end-to-end tests against a local origin server
```

## License

MIT — see [LICENSE](LICENSE).
