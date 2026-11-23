"""Async HTTP forward proxy + reverse proxy. Standard library only.

Forward mode:
  - Plain HTTP requests are forwarded to the origin and relayed back.
  - CONNECT establishes a raw TCP tunnel (TLS passes through encrypted,
    the proxy never sees the plaintext).

Reverse mode:
  - Every request is forwarded to a single configured upstream.

Only connection metadata is logged: method, host, status, byte counts,
and duration. Headers / bodies are not logged.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
from collections import Counter, deque
import os
import sys
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}
MAX_HEAD = 64 * 1024
BUFFER = 64 * 1024


# Payload capture is hard-disabled for these suffixes, whatever the env says:
# this build is for debugging the operator's own servers, not Bilibili's.
PAYLOAD_FORBIDDEN_SUFFIXES = ("bilibili.com", "bilibiligame.net", "bilibili.tv")

LUMI_WATCH_HOSTS = (
    "*.bilibiligame.net", "*.bilibili.com", "*.bilibili.tv",
    "lumigo-cn-prod-vs.bilibiligame.net", "lumigo-cn-test-vs.bilibiligame.net",
    "lumigo-sg-prod-vs.bilibiligame.net", "lumigo-sg-test-vs.bilibiligame.net",
    "lumigo-jp-prod-vs.bilibiligame.net", "lumigo-cn-prod-log.bilibiligame.net",
)

@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8080
    mode: str = "forward"          # "forward" | "reverse"
    upstream: str = ""             # reverse mode only, e.g. http://127.0.0.1:9000
    auth: str = ""                 # "user:password" or "" for no auth
    timeout: float = 30.0
    cache_ttl: float = 0.0         # seconds; 0 = cache off
    cache_max_entries: int = 128
    cache_max_bytes: int = 1024 * 1024
    rate_limit: int = 0            # requests/minute per client IP; 0 = off
    block_hosts: tuple = ()        # patterns: example.com or *.example.com
    allow_hosts: tuple = ()        # if set, only these hosts are allowed
    log_file: str = ""
    log_format: str = "text"       # "text" | "json"
    watch_hosts: tuple = ()        # metadata watchlist patterns (see --lumi)
    payload_capture: bool = False  # body capture, own hosts only (see below)
    payload_allow_hosts: tuple = ()  # explicit env allowlist for capture
    payload_max_bytes: int = 4096
    payload_aes_key: str = ""      # env only: hex (32 chars) or raw 16 chars
    payload_aes_iv: str = ""       # env only: hex (32 chars) or raw 16 chars
    payload_lgeb: bool = False     # LGEB-format reader, own hosts only
    payload_lgeb_salt_hex: str = ""  # env only: YOUR server A's salt, 32 hex
    payload_lgeb_content_hash: str = ""  # env only, optional override
    intercept: bool = False        # hold/release/drop, own hosts only
    intercept_allow_hosts: tuple = ()  # explicit env allowlist for intercept
    intercept_timeout: float = 30.0  # seconds a held item waits, then forwards

    def check_auth(self, headers: dict[str, str]) -> bool:
        if not self.auth:
            return True
        expected = "Basic " + base64.b64encode(self.auth.encode()).decode()
        return headers.get("proxy-authorization") == expected or \
            headers.get("authorization") == expected


def parse_head(raw: bytes) -> tuple[str, dict[str, str], bytes]:
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers, rest


async def read_head(reader: asyncio.StreamReader) -> bytes | None:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await reader.read(4096)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > MAX_HEAD:
            raise ValueError("request head too large")
    return buf


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               counter: list[int]) -> None:
    try:
        while True:
            data = await reader.read(BUFFER)
            if not data:
                break
            counter[0] += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def payload_forbidden(host: str) -> bool:
    h = str(host).split(":")[0].lower()
    return any(h == suf or h.endswith("." + suf)
               for suf in PAYLOAD_FORBIDDEN_SUFFIXES)


def _decode_key_material(value: str) -> bytes:
    v = value.strip()
    if len(v) == 32:
        try:
            return bytes.fromhex(v)
        except ValueError:
            pass
    return v.encode()


def preview_bytes(data: bytes, limit: int) -> dict:
    shown = data[:limit]
    try:
        text = shown.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return {"kind": "text", "preview": text,
                    "size": len(data), "truncated": len(data) > limit}
    except UnicodeDecodeError:
        pass
    return {"kind": "hex", "preview": shown.hex(" "),
            "size": len(data), "truncated": len(data) > limit}


def try_aes_decrypt(data: bytes, key_s: str, iv_s: str) -> dict | None:
    """Optional AES-128-CBC / PKCS#7 decrypt of a captured body.

    Uses the operator's OWN key/IV from the environment. Needs the
    `cryptography` package; without it, returns an explanatory note
    instead of failing the request.
    """
    if not key_s or not iv_s or not data:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return {"kind": "note",
                "preview": "PAYLOAD_AES_KEY/IV are set but the `cryptography` "
                           "package is not installed; showing raw body only.",
                "size": len(data), "truncated": False}
    try:
        key, iv = _decode_key_material(key_s), _decode_key_material(iv_s)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plain = decryptor.update(data) + decryptor.finalize()
        if plain and 1 <= plain[-1] <= 16:  # PKCS#7 strip
            plain = plain[:-plain[-1]]
        return preview_bytes(plain, 4096)
    except Exception as exc:
        return {"kind": "note", "preview": f"AES decrypt failed: {exc!r}",
                "size": len(data), "truncated": False}


def extract_content_hash(name: str) -> str:
    """LGEB naming rule: 32-hex suffix after the last '_' before '.bundle'."""
    base = str(name).split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    if base.lower().endswith(".bundle"):
        base = base[:-7]
    tail = base.rsplit("_", 1)[-1].lower()
    if len(tail) == 32 and all(c in "0123456789abcdef" for c in tail):
        return tail
    return ""


def try_lgeb_decrypt(data: bytes, salt_hex: str, content_hash: str,
                     limit: int = 4096) -> dict | None:
    """Read an LGEB-format body from the operator's OWN server A.

    Format: b'LGEB' + resVersion (u32 LE) + AES-128-CBC/PKCS#7 ciphertext.
    Key/IV derivation (same *structure* as traced): SHA-256 of
    salt + UTF8(f"{contentHash}:{resVersion}"), key = digest[:16],
    iv = digest[16:]. The salt is NOT built in: it must be server A's
    own salt, supplied via PAYLOAD_LGEB_SALT_HEX in the environment.
    Without it — or without a contentHash (from the file name in the
    request target, or PAYLOAD_LGEB_CONTENT_HASH) — no decryption is
    attempted. Needs the `cryptography` package, like try_aes_decrypt.
    """
    if not data or data[:4] != b"LGEB" or len(data) < 8 + 16:
        return None
    res_version = int.from_bytes(data[4:8], "little")
    if not salt_hex:
        return {"kind": "note",
                "preview": "LGEB body seen, but PAYLOAD_LGEB_SALT_HEX is "
                           "not set; server B cannot derive the key without "
                           "server A's salt in env.",
                "size": len(data), "truncated": False}
    if not content_hash:
        return {"kind": "note",
                "preview": "LGEB body seen, but no contentHash could be "
                           "taken from the target file name and "
                           "PAYLOAD_LGEB_CONTENT_HASH is not set.",
                "size": len(data), "truncated": False}
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return {"kind": "note",
                "preview": "LGEB body seen but the `cryptography` package "
                           "is not installed; showing raw body only.",
                "size": len(data), "truncated": False}
    try:
        salt = _decode_key_material(salt_hex)
        digest = hashlib.sha256(
            salt + f"{content_hash}:{res_version}".encode()).digest()
        decryptor = Cipher(algorithms.AES(digest[:16]),
                           modes.CBC(digest[16:])).decryptor()
        plain = decryptor.update(data[8:]) + decryptor.finalize()
        if plain and 1 <= plain[-1] <= 16:
            plain = plain[:-plain[-1]]
        out = preview_bytes(plain, limit)
        out["lgeb"] = {"res_version": res_version,
                       "content_hash": content_hash}
        return out
    except Exception as exc:
        return {"kind": "note", "preview": f"LGEB decrypt failed: {exc!r}",
                "size": len(data), "truncated": False}


def host_matches(host: str, patterns) -> bool:
    h = host.split(":")[0].lower()
    for pat in patterns:
        pat = pat.lower()
        if pat.startswith("*."):
            if h == pat[2:] or h.endswith(pat[1:]):
                return True
        elif h == pat:
            return True
    return False


class Stats:
    def __init__(self):
        self.started = time.time()
        self.requests = 0
        self.errors = 0
        self.bytes_sent = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.rate_limited = 0
        self.blocked = 0
        self.by_status = Counter()
        self.by_host = Counter()
        self.recent: deque = deque(maxlen=200)
        self.watch_patterns: tuple = ()

    _next_id = 0

    def record_event(self, ts, method, host, status, nbytes, duration_ms,
                     peer="-", target="-", payload=None):
        Stats._next_id += 1
        self.recent.appendleft({
            "id": Stats._next_id,
            "time": ts, "method": method, "host": host, "status": status,
            "bytes": nbytes, "duration_ms": duration_ms,
            "peer": peer, "target": target, "payload": payload,
            "watched": bool(self.watch_patterns and host
                            and host_matches(str(host), self.watch_patterns)),
        })

    def record(self, host, status, nbytes):
        self.requests += 1
        self.bytes_sent += nbytes
        self.by_status[str(status)] += 1
        if host and host != "-":
            self.by_host[str(host)] += 1
        if status >= 500:
            self.errors += 1

    def snapshot(self) -> dict:
        return {
            "uptime_seconds": round(time.time() - self.started, 1),
            "requests": self.requests, "errors": self.errors,
            "bytes_sent": self.bytes_sent,
            "cache_hits": self.cache_hits, "cache_misses": self.cache_misses,
            "rate_limited": self.rate_limited, "blocked": self.blocked,
            "by_status": dict(self.by_status),
            "top_hosts": self.by_host.most_common(10),
            "recent": list(self.recent),
            "watch": self.watch_snapshot(),
        }

    def watch_snapshot(self) -> dict:
        watched = [e for e in self.recent if e.get("watched")]
        hosts = Counter(e["host"] for e in watched)
        return {
            "patterns": list(self.watch_patterns),
            "events_in_recent": len(watched),
            "total_requests": sum(c for h, c in self.by_host.items()
                                  if self.watch_patterns
                                  and host_matches(str(h), self.watch_patterns)),
            "hosts": hosts.most_common(10),
            "recent": watched[:50],
        }


class RateLimiter:
    """Fixed-window limiter: N requests per 60s per key."""
    def __init__(self, limit: int):
        self.limit = limit
        self.windows: dict[str, list] = {}

    def allow(self, key: str) -> bool:
        if not self.limit:
            return True
        now = time.time()
        start, count = self.windows.get(key, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        count += 1
        self.windows[key] = [start, count]
        return count <= self.limit


class Cache:
    def __init__(self, ttl: float, max_entries: int, max_bytes: int):
        self.ttl, self.max_entries, self.max_bytes = ttl, max_entries, max_bytes
        self.store: dict[str, tuple[float, bytes]] = {}

    def get(self, key: str):
        if not self.ttl:
            return None
        item = self.store.get(key)
        if not item:
            return None
        expiry, data = item
        if time.time() > expiry:
            del self.store[key]
            return None
        return data

    def put(self, key: str, data: bytes):
        if not self.ttl or len(data) > self.max_bytes:
            return
        if len(self.store) >= self.max_entries:
            self.store.pop(next(iter(self.store)))
        self.store[key] = (time.time() + self.ttl, data)


SECRET_ENV_KEYS = ("PAYLOAD_LGEB_SALT_HEX", "PAYLOAD_AES_KEY", "PAYLOAD_AES_IV")


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def update_env_file(path: str, updates: dict[str, str]) -> None:
    """Merge KEY=VALUE updates into a .env file, preserving other lines."""
    lines: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        pass
    seen = set()
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                out.append(f"{key}={updates[key]}")
                seen.add(key)
                continue
        out.append(line)
    for key, value in updates.items():
        if key not in seen:
            out.append(f"{key}={value}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")


class Proxy:
    def __init__(self, config: Config):
        self.cfg = config
        self.intercepts: dict[int, dict] = {}
        self._intercept_seq = 0
        self.stats = Stats()
        self.stats.watch_patterns = tuple(config.watch_hosts)
        self.limiter = RateLimiter(config.rate_limit)
        self.cache = Cache(config.cache_ttl, config.cache_max_entries,
                           config.cache_max_bytes)

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        start = time.monotonic()
        peer = writer.get_extra_info("peername")
        method = host = "-"
        target = "-"
        status = 0
        detail: dict = {}
        sent = [0]
        try:
            raw = await asyncio.wait_for(read_head(reader), self.cfg.timeout)
            if raw is None:
                return
            first, headers, rest = parse_head(raw)
            parts = first.split(" ")
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]

            if target in ("/__dashboard", "/dashboard"):
                body = DASHBOARD_HTML.encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            if target.split("?")[0] in ("/__config", "/config"):
                from urllib.parse import parse_qs
                if method.upper() == "POST":
                    body_bytes = rest
                    length = headers.get("content-length")
                    if length:
                        remaining = int(length) - len(rest)
                        while remaining > 0:
                            chunk = await reader.read(
                                min(BUFFER, remaining))
                            if not chunk:
                                break
                            body_bytes += chunk
                            remaining -= len(chunk)
                    form = parse_qs(body_bytes.decode("utf-8", "replace"))
                    persist = _truthy(form.get("PERSIST", ["1"])[0])
                    result = self.apply_config(form, persist)
                    body = json.dumps(result).encode()
                else:
                    body = json.dumps(self.config_snapshot()).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            if target.startswith("/__intercepts"):
                body = json.dumps(
                    {"pending": self.intercept_snapshot()}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            if target.startswith("/__intercept/release") or \
                    target.startswith("/__intercept/drop"):
                from urllib.parse import parse_qs, urlsplit as _us
                action = "release" if "/release" in target else "drop"
                q = parse_qs(_us(target).query)
                try:
                    item_id = int(q.get("id", ["0"])[0])
                except ValueError:
                    item_id = 0
                ok = self.resolve_intercept(item_id, action)
                body = json.dumps({"ok": ok, "id": item_id,
                                   "action": action}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            if target in ("/__stats", "/stats"):
                body = json.dumps(self.stats.snapshot()).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            if target in ("/__health", "/health"):
                body = b'{"status":"ok"}'
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            client_ip = peer[0] if peer else "-"
            if not self.limiter.allow(client_ip):
                self.stats.rate_limited += 1
                writer.write(b"HTTP/1.1 429 Too Many Requests\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                status = 429
                return

            if not self.cfg.check_auth(headers):
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b'Proxy-Authenticate: Basic realm="proxy"\r\n'
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                status = 407
                return

            raw_host = target if method.upper() == "CONNECT" else (
                urlsplit(target).netloc or headers.get("host", ""))
            if raw_host and self.cfg.mode == "forward":
                if host_matches(raw_host, self.cfg.block_hosts) or (
                    self.cfg.allow_hosts
                    and not host_matches(raw_host, self.cfg.allow_hosts)
                ):
                    self.stats.blocked += 1
                    writer.write(b"HTTP/1.1 403 Forbidden\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    status = 403
                    host = raw_host
                    return

            if method.upper() == "CONNECT":
                host = target
                status = await self._tunnel(reader, writer, target, sent)
            elif self.cfg.mode == "reverse":
                host = self.cfg.upstream
                status = await self._forward(reader, writer, first, headers,
                                             rest, self.cfg.upstream, target, sent,
                                             detail)
            else:
                host = urlsplit(target).netloc or headers.get("host", "-")
                status = await self._forward(reader, writer, first, headers,
                                             rest, None, target, sent, detail)
        except Exception as exc:  # keep the server alive on any client error
            status = status or 502
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            print(f"proxy error: {exc!r}", file=sys.stderr)
        finally:
            dur = int((time.monotonic() - start) * 1000)
            self.stats.record(host, status, sent[0])
            self.stats.record_event(time.strftime("%H:%M:%S"), method, host,
                                    status, sent[0], dur,
                                    peer=str(peer), target=str(target),
                                    payload=detail.get("payload"))
            if self.cfg.log_format == "json":
                line = json.dumps({"peer": str(peer), "method": method,
                                   "host": host, "status": status,
                                   "bytes": sent[0], "duration_ms": dur})
            else:
                line = f"{peer} {method} {host} {status} {sent[0]}B {dur}ms"
            print(line, flush=True)
            if self.cfg.log_file:
                try:
                    with open(self.cfg.log_file, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError:
                    pass
            try:
                writer.close()
            except Exception:
                pass

    async def _tunnel(self, reader, writer, target: str, sent: list[int]) -> int:
        host, _, port = target.partition(":")
        up_reader, up_writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port or 443)), self.cfg.timeout)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        received = [0]
        await asyncio.gather(
            pipe(reader, up_writer, sent),
            pipe(up_reader, writer, received),
        )
        return 200

    def _intercept_enabled_for(self, host: str) -> bool:
        if not self.cfg.intercept:
            return False
        if payload_forbidden(host):
            return False
        return bool(self.cfg.intercept_allow_hosts
                    and host_matches(host, self.cfg.intercept_allow_hosts))

    def config_snapshot(self) -> dict:
        """Effective config for the dashboard. Secrets are never returned:
        only whether each one is set."""
        c = self.cfg
        return {
            "PAYLOAD_CAPTURE": c.payload_capture,
            "PAYLOAD_ALLOW_HOSTS": ",".join(c.payload_allow_hosts),
            "PAYLOAD_MAX_BYTES": c.payload_max_bytes,
            "PAYLOAD_LGEB": c.payload_lgeb,
            "PAYLOAD_LGEB_CONTENT_HASH": c.payload_lgeb_content_hash,
            "INTERCEPT": c.intercept,
            "INTERCEPT_ALLOW_HOSTS": ",".join(c.intercept_allow_hosts),
            "INTERCEPT_TIMEOUT": c.intercept_timeout,
            "PROXY_CACHE_TTL": c.cache_ttl,
            "PROXY_RATE_LIMIT": c.rate_limit,
            "PROXY_LOG_FORMAT": c.log_format,
            "secrets_set": {
                "PAYLOAD_LGEB_SALT_HEX": bool(c.payload_lgeb_salt_hex),
                "PAYLOAD_AES_KEY": bool(c.payload_aes_key),
                "PAYLOAD_AES_IV": bool(c.payload_aes_iv),
            },
            "restart_only": {"PROXY_HOST": c.host, "PROXY_PORT": c.port,
                             "PROXY_MODE": c.mode,
                             "PROXY_UPSTREAM": c.upstream},
        }

    def apply_config(self, form: dict, persist: bool) -> dict:
        """Apply dashboard settings: live where possible, .env if persist.

        Secret fields are set-only: an empty value leaves the current
        secret untouched. Bind settings (host/port/mode/upstream) are
        persisted for the next start and reported as restart-only.
        """
        c = self.cfg
        applied, env_updates, restart_only = [], {}, []

        def take(key):
            return form.get(key, [None])[0]

        def set_bool(key, attr):
            v = take(key)
            if v is not None:
                val = _truthy(v)
                setattr(c, attr, val)
                env_updates[key] = "1" if val else "0"
                applied.append(key)

        def set_csv(key, attr):
            v = take(key)
            if v is not None:
                setattr(c, attr, _csv(v))
                env_updates[key] = v
                applied.append(key)

        def set_num(key, attr, cast):
            v = take(key)
            if v is not None and v != "":
                try:
                    setattr(c, attr, cast(v))
                    env_updates[key] = v
                    applied.append(key)
                except ValueError:
                    pass

        def set_str(key, attr):
            v = take(key)
            if v is not None:
                setattr(c, attr, v)
                env_updates[key] = v
                applied.append(key)

        def set_secret(key, attr):
            v = take(key)
            if v:  # empty = keep current secret
                setattr(c, attr, v)
                env_updates[key] = v
                applied.append(key)

        set_bool("PAYLOAD_CAPTURE", "payload_capture")
        set_csv("PAYLOAD_ALLOW_HOSTS", "payload_allow_hosts")
        set_num("PAYLOAD_MAX_BYTES", "payload_max_bytes", int)
        set_bool("PAYLOAD_LGEB", "payload_lgeb")
        set_str("PAYLOAD_LGEB_CONTENT_HASH", "payload_lgeb_content_hash")
        set_bool("INTERCEPT", "intercept")
        set_csv("INTERCEPT_ALLOW_HOSTS", "intercept_allow_hosts")
        set_num("INTERCEPT_TIMEOUT", "intercept_timeout", float)
        set_num("PROXY_CACHE_TTL", "cache_ttl", float)
        set_num("PROXY_RATE_LIMIT", "rate_limit", int)
        set_str("PROXY_LOG_FORMAT", "log_format")
        set_secret("PAYLOAD_LGEB_SALT_HEX", "payload_lgeb_salt_hex")
        set_secret("PAYLOAD_AES_KEY", "payload_aes_key")
        set_secret("PAYLOAD_AES_IV", "payload_aes_iv")
        for key, attr in (("PROXY_HOST", "host"), ("PROXY_PORT", "port"),
                          ("PROXY_MODE", "mode"),
                          ("PROXY_UPSTREAM", "upstream")):
            v = take(key)
            if v is not None and str(v) != str(getattr(c, attr)):
                env_updates[key] = str(v)
                restart_only.append(key)
        # keep dependent objects in sync with the live values
        self.cache.ttl = c.cache_ttl
        self.limiter.limit = c.rate_limit
        persisted = False
        if persist and env_updates:
            path = os.getenv("PROXY_ENV_FILE", ".env")
            update_env_file(path, env_updates)
            for k, v in env_updates.items():
                os.environ[k] = v
            persisted = True
        return {"ok": True, "applied": applied, "persisted": persisted,
                "restart_required_for": restart_only}

    def intercept_snapshot(self) -> list:
        return [{k: v for k, v in item.items() if k != "event"}
                for item in self.intercepts.values()]

    def resolve_intercept(self, item_id: int, action: str) -> bool:
        item = self.intercepts.get(item_id)
        if not item:
            return False
        item["action"] = action
        item["event"].set()
        return True

    async def _hold(self, phase: str, method: str, host: str,
                    target: str, body: bytes) -> bool:
        """Park one phase of a connection until released/dropped/timeout.

        Returns True to let it continue, False to drop it. Timeout
        forwards (True) so a forgotten dashboard tab cannot wedge
        the operator's own traffic forever.
        """
        self._intercept_seq += 1
        item_id = self._intercept_seq
        event = asyncio.Event()
        item = {
            "id": item_id, "phase": phase, "method": method,
            "host": host, "target": target,
            "body": preview_bytes(body, self.cfg.payload_max_bytes)
            if body else None,
            "action": "pending", "event": event,
        }
        self.intercepts[item_id] = item
        try:
            await asyncio.wait_for(event.wait(),
                                   self.cfg.intercept_timeout)
        except asyncio.TimeoutError:
            return True
        finally:
            self.intercepts.pop(item_id, None)
        return item["action"] != "drop"

    def _capture_enabled_for(self, host: str) -> bool:
        if not self.cfg.payload_capture:
            return False
        if payload_forbidden(host):
            return False
        return bool(self.cfg.payload_allow_hosts
                    and host_matches(host, self.cfg.payload_allow_hosts))

    async def _forward(self, reader, writer, first, headers, rest,
                       upstream_base, target, sent, detail=None) -> int:
        if upstream_base:
            base = urlsplit(upstream_base)
            host, port = base.hostname, base.port or 80
            path = target if target.startswith("/") else "/" + target
            origin_first = f"{first.split(' ')[0]} {path} HTTP/1.1"
        else:
            u = urlsplit(target)
            if not u.hostname:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return 400
            host, port = u.hostname, u.port or 80
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            origin_first = f"{first.split(' ')[0]} {path} HTTP/1.1"

        capture = self._capture_enabled_for(f"{host}:{port}") or \
            self._capture_enabled_for(host)
        intercept = self._intercept_enabled_for(f"{host}:{port}") or \
            self._intercept_enabled_for(host)

        # Read the full request body first (bounded by Content-Length).
        req_body = rest
        length = headers.get("content-length")
        if length:
            remaining = int(length) - len(rest)
            while remaining > 0:
                chunk = await reader.read(min(BUFFER, remaining))
                if not chunk:
                    break
                req_body += chunk
                remaining -= len(chunk)

        # Intercept (transfer): hold the request before it reaches A.
        if intercept:
            method = first.split(" ")[0]
            if not await self._hold("request", method, host, target,
                                    req_body):
                writer.write(b"HTTP/1.1 403 Forbidden\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return 403

        cache_key = None
        if first.split(" ")[0].upper() == "GET":
            cache_key = f"{host}:{port}{path}"
            hit = self.cache.get(cache_key)
            if hit is not None:
                self.stats.cache_hits += 1
                writer.write(hit)
                await writer.drain()
                line = hit.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                pp = line.split(" ")
                return int(pp[1]) if len(pp) >= 2 and pp[1].isdigit() else 200
            if self.cfg.cache_ttl:
                self.stats.cache_misses += 1

        up_reader, up_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), self.cfg.timeout)

        raw_headers = []
        seen_host = False
        for k, v in headers.items():
            if k in HOP_BY_HOP:
                continue
            if k == "host":
                seen_host = True
            raw_headers.append(f"{k}: {v}")
        if not seen_host:
            raw_headers.append(f"host: {host}")
        raw_headers.append("connection: close")
        head = ("\r\n".join([origin_first] + raw_headers) + "\r\n\r\n").encode("iso-8859-1")
        up_writer.write(head + req_body)
        sent[0] += len(head) + len(req_body)
        await up_writer.drain()
        try:
            up_writer.write_eof()  # half-close: request done, response still open
        except Exception:
            pass

        status = 502
        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                data = await asyncio.wait_for(up_reader.read(BUFFER),
                                              self.cfg.timeout)
                if not data:
                    break
                if total == 0:
                    line = data.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                    pp = line.split(" ")
                    if len(pp) >= 2 and pp[1].isdigit():
                        status = int(pp[1])
                chunks.append(data)
                total += len(data)
                if not intercept:
                    writer.write(data)
                    await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if not intercept:
                try:
                    writer.close()
                except Exception:
                    pass

        response = b"".join(chunks)

        # Intercept (receive): hold the response before it reaches the client.
        if intercept:
            resp_body = response.partition(b"\r\n\r\n")[2]
            method = first.split(" ")[0]
            if await self._hold("response", method, host, target, resp_body):
                try:
                    writer.write(response)
                    await writer.drain()
                except Exception:
                    pass
            else:
                status = 502
                try:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                except Exception:
                    pass
        if cache_key and status == 200 and total <= self.cfg.cache_max_bytes:
            self.cache.put(cache_key, response)

        if capture and detail is not None:
            resp_body = response.partition(b"\r\n\r\n")[2]
            payload = {
                "request": preview_bytes(req_body, self.cfg.payload_max_bytes)
                if req_body else None,
                "response": preview_bytes(resp_body, self.cfg.payload_max_bytes)
                if resp_body else None,
            }
            dec_req = try_aes_decrypt(req_body, self.cfg.payload_aes_key,
                                      self.cfg.payload_aes_iv) if req_body else None
            dec_resp = try_aes_decrypt(resp_body, self.cfg.payload_aes_key,
                                       self.cfg.payload_aes_iv) if resp_body else None
            if dec_req:
                payload["request_decrypted"] = dec_req
            if dec_resp:
                payload["response_decrypted"] = dec_resp
            if self.cfg.payload_lgeb:
                chash = self.cfg.payload_lgeb_content_hash or \
                    extract_content_hash(target)
                lg_req = try_lgeb_decrypt(
                    req_body, self.cfg.payload_lgeb_salt_hex, chash,
                    self.cfg.payload_max_bytes) if req_body else None
                lg_resp = try_lgeb_decrypt(
                    resp_body, self.cfg.payload_lgeb_salt_hex, chash,
                    self.cfg.payload_max_bytes) if resp_body else None
                if lg_req:
                    payload["request_lgeb"] = lg_req
                if lg_resp:
                    payload["response_lgeb"] = lg_resp
            detail["payload"] = payload
        return status

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxy-server dashboard</title>
<style>
body{font-family:system-ui,sans-serif;margin:24px;background:#0f1115;color:#e6e6e6}
h1{font-size:20px} h2{font-size:15px;margin-top:28px;color:#9fd}
.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#1a1d24;border:1px solid #2a2e38;border-radius:10px;padding:14px 18px;min-width:120px}
.card b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%;margin-top:8px}
td,th{border-bottom:1px solid #2a2e38;padding:6px 8px;text-align:left;font-size:13px}
.watch{color:#ffd479} .muted{color:#8a90a0} .err{color:#ff7b7b}
</style></head><body>
<h1>proxy-server dashboard <span class="muted">— metadata only (host · status · bytes · duration)</span></h1>
<div class="cards" id="cards"></div>
<h2>Lumi / watchlist traffic</h2>
<div id="watch" class="muted">no watchlist configured — start with <code>--lumi</code> or <code>--watch HOST</code></div>
<table id="watchTable"></table>
<h2>Settings — edit env from here</h2>
<div class="card" style="display:block">
<div id="settingsForm">loading settings…</div>
<label><input type="checkbox" id="setPersist" checked> also save to .env (applies on next start too)</label>
<button onclick="saveSettings()">Save settings</button>
<span id="settingsMsg" class="muted"></span>
</div>
<h2>Intercept — held traffic (own hosts only)</h2>
<div id="intercepts" class="muted">intercept off — set <code>INTERCEPT=1</code> + <code>INTERCEPT_ALLOW_HOSTS</code> in env</div>
<h2>Connection detail</h2>
<div id="detail" class="card" style="display:block">Click a row in Recent traffic to see its detail. Payload is shown only for your own hosts listed in PAYLOAD_ALLOW_HOSTS.</div>
<h2>Recent traffic through the proxy</h2>
<table id="recent"><tr><th>time</th><th>method</th><th>host</th><th>status</th><th>bytes</th><th>ms</th><th></th></tr></table>
<h2>Top hosts</h2>
<table id="tops"></table>
<script>
async function tick(){
  const s = await (await fetch('/__stats')).json();
  const c = [['Requests',s.requests],['Errors',s.errors],['Bytes sent',s.bytes_sent],
    ['Cache hits',s.cache_hits],['Cache misses',s.cache_misses],
    ['Rate limited',s.rate_limited],['Blocked',s.blocked],['Uptime (s)',s.uptime_seconds]];
  document.getElementById('cards').innerHTML =
    c.map(x=>`<div class="card"><span class="muted">${x[0]}</span><b>${x[1]}</b></div>`).join('');
  const w = s.watch || {};
  if ((w.patterns||[]).length){
    document.getElementById('watch').innerHTML =
      `<span class="watch">${w.total_requests} watched requests</span> · patterns: ${w.patterns.join(', ')}`;
    document.getElementById('watchTable').innerHTML =
      '<tr><th>host</th><th>requests (recent window)</th></tr>' +
      (w.hosts||[]).map(h=>`<tr><td class="watch">${h[0]}</td><td>${h[1]}</td></tr>`).join('');
  }
  window._recent = s.recent || [];
  document.getElementById('recent').innerHTML =
    '<tr><th>time</th><th>method</th><th>host</th><th>status</th><th>bytes</th><th>ms</th><th></th></tr>' +
    window._recent.slice(0,50).map((e,i)=>
      `<tr onclick="showDetail(${i})" style="cursor:pointer"><td>${e.time}</td><td>${e.method}</td><td class="${e.watched?'watch':''}">${e.host}</td>`+
      `<td class="${e.status>=500?'err':''}">${e.status}</td><td>${e.bytes}</td><td>${e.duration_ms}</td>`+
      `<td>${e.watched?'<span class="watch">● watched</span>':''}</td></tr>`).join('');
  try {
    const ij = await (await fetch('/__intercepts')).json();
    const pend = ij.pending || [];
    if (pend.length){
      document.getElementById('intercepts').innerHTML =
        pend.map(p=>`<div class="card" style="display:block;margin:6px 0">#${p.id} <b>${p.phase}</b> ${p.method} ${p.host} ${p.target}`+
        (p.body?` <span class="muted">${p.body.kind} ${p.body.size}B: ${String(p.body.preview).slice(0,120)}</span>`:'')+
        ` <button onclick="resolveIntercept(${p.id},'release')">Release</button>`+
        ` <button onclick="resolveIntercept(${p.id},'drop')">Drop</button></div>`).join('');
    } else {
      document.getElementById('intercepts').innerHTML = '<span class="muted">nothing held right now</span>';
    }
  } catch(e) {}
  document.getElementById('tops').innerHTML =
    '<tr><th>host</th><th>requests</th></tr>' +
    (s.top_hosts||[]).map(h=>`<tr><td>${h[0]}</td><td>${h[1]}</td></tr>`).join('');
}
const SET_BOOL = ['PAYLOAD_CAPTURE','PAYLOAD_LGEB','INTERCEPT'];
const SET_TEXT = ['PAYLOAD_ALLOW_HOSTS','PAYLOAD_MAX_BYTES','PAYLOAD_LGEB_CONTENT_HASH',
  'INTERCEPT_ALLOW_HOSTS','INTERCEPT_TIMEOUT','PROXY_CACHE_TTL','PROXY_RATE_LIMIT','PROXY_LOG_FORMAT'];
const SET_SECRET = ['PAYLOAD_LGEB_SALT_HEX','PAYLOAD_AES_KEY','PAYLOAD_AES_IV'];
async function loadSettings(){
  try {
    const c = await (await fetch('/__config')).json();
    let h = '';
    for (const k of SET_BOOL)
      h += `<label style="display:block"><input type="checkbox" id="cfg_${k}" ${c[k]?'checked':''}> ${k}</label>`;
    for (const k of SET_TEXT)
      h += `<label style="display:block">${k} <input id="cfg_${k}" value="${String(c[k]??'').replace(/"/g,'&quot;')}" size="42"></label>`;
    for (const k of SET_SECRET)
      h += `<label style="display:block">${k} <input type="password" id="cfg_${k}" size="42" placeholder="${c.secrets_set[k]?'set — leave blank to keep':'not set'}"></label>`;
    const r = c.restart_only || {};
    h += `<div class="muted">restart-only (saved to .env, applied next start): PROXY_HOST=${r.PROXY_HOST} · PROXY_PORT=${r.PROXY_PORT} · PROXY_MODE=${r.PROXY_MODE}</div>`;
    document.getElementById('settingsForm').innerHTML = h;
  } catch(e) {}
}
window.saveSettings = async function(){
  const body = new URLSearchParams();
  for (const k of SET_BOOL) body.set(k, document.getElementById('cfg_'+k).checked ? '1' : '0');
  for (const k of SET_TEXT) body.set(k, document.getElementById('cfg_'+k).value);
  for (const k of SET_SECRET){ const v = document.getElementById('cfg_'+k).value; if (v) body.set(k, v); }
  body.set('PERSIST', document.getElementById('setPersist').checked ? '1' : '0');
  const r = await (await fetch('/__config', {method:'POST', body})).json();
  document.getElementById('settingsMsg').textContent =
    'saved: ' + (r.applied||[]).join(', ') + (r.persisted ? ' · written to .env' : ' · live only') +
    ((r.restart_required_for||[]).length ? ' · restart needed for ' + r.restart_required_for.join(', ') : '');
  loadSettings();
};
loadSettings();
window.resolveIntercept = async function(id, action){
  await fetch('/__intercept/' + action + '?id=' + id);
  tick();
};
window.showDetail = function(i){
  const e = (window._recent||[])[i]; if(!e) return;
  const rows = [['Connection #',e.id],['Time',e.time],['Client (peer)',e.peer],
    ['Method',e.method],['Host',e.host],['Target / path',e.target],
    ['Status',e.status],['Bytes (request side)',e.bytes],['Duration',e.duration_ms+' ms'],
    ['Watched (Lumi watchlist)',e.watched?'yes':'no']];
  if (e.payload){
    for (const k of ['request','response','request_decrypted','response_decrypted','request_lgeb','response_lgeb']){
      const v = e.payload[k];
      if (v) rows.push([k+' ('+v.kind+', '+v.size+' B'+(v.truncated?', truncated':'')+')',
                        '<pre style="white-space:pre-wrap;word-break:break-all">'+
                        String(v.preview).replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</pre>']);
    }
  } else {
    rows.push(['Payload','not captured for this host (enable PAYLOAD_CAPTURE + PAYLOAD_ALLOW_HOSTS for your own server)']);
  }
  document.getElementById('detail').innerHTML =
    '<b>Connection detail</b><table>' +
    rows.map(r=>`<tr><td class="muted">${r[0]}</td><td>${r[1]}</td></tr>`).join('') + '</table>';
};
tick(); setInterval(tick, 2000);
</script></body></html>
"""


def load_env_file(path: str = ".env") -> None:
    """Load KEY=VALUE lines from a local .env into os.environ (no override)."""
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))
    except OSError:
        pass


def _csv(value: str) -> tuple:
    return tuple(x.strip() for x in value.split(",") if x.strip())


def config_from_env_and_args(argv=None) -> Config:
    load_env_file(os.getenv("PROXY_ENV_FILE", ".env"))
    p = argparse.ArgumentParser(prog="proxy-server", description=__doc__)
    p.add_argument("--host", default=os.getenv("PROXY_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("PROXY_PORT", "8080")))
    p.add_argument("--mode", choices=["forward", "reverse"], default=os.getenv("PROXY_MODE", "forward"))
    p.add_argument("--upstream", default=os.getenv("PROXY_UPSTREAM", ""))
    p.add_argument("--auth", default=os.getenv("PROXY_AUTH", ""), help="'user:password'")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--cache-ttl", type=float, default=float(os.getenv("PROXY_CACHE_TTL", "0")),
                   help="cache GET responses for N seconds (0 = off)")
    p.add_argument("--rate-limit", type=int, default=int(os.getenv("PROXY_RATE_LIMIT", "0")),
                   help="max requests/minute per client IP (0 = off)")
    p.add_argument("--block", action="append", default=[],
                   help="blocked host pattern, repeatable (e.g. *.ads.example)")
    p.add_argument("--allow", action="append", default=[],
                   help="if set, only these host patterns are allowed")
    p.add_argument("--log-file", default=os.getenv("PROXY_LOG_FILE", ""))
    p.add_argument("--log-format", choices=["text", "json"],
                   default=os.getenv("PROXY_LOG_FORMAT", "text"))
    p.add_argument("--config", default="", help="JSON config file; CLI flags win")
    p.add_argument("--payload-capture", action="store_true",
                   default=os.getenv("PAYLOAD_CAPTURE", "") in ("1", "true", "yes"),
                   help="capture request/response bodies for PAYLOAD_ALLOW_HOSTS only")
    p.add_argument("--payload-lgeb", action="store_true",
                   default=os.getenv("PAYLOAD_LGEB", "") in ("1", "true", "yes"),
                   help="also try the LGEB-format reader on captured bodies "
                        "(needs PAYLOAD_LGEB_SALT_HEX in env)")
    p.add_argument("--intercept", action="store_true",
                   default=os.getenv("INTERCEPT", "") in ("1", "true", "yes"),
                   help="hold request/response for INTERCEPT_ALLOW_HOSTS "
                        "until released/dropped from the dashboard")
    p.add_argument("--watch", action="append", default=[],
                   help="watchlist host pattern for the dashboard, repeatable")
    p.add_argument("--lumi", action="store_true",
                   help="preset watchlist: Lumi Master / Bilibili endpoints "
                        "(metadata only: host, timing, size, status)")
    a = p.parse_args(argv)
    file_cfg = {}
    if a.config:
        with open(a.config, encoding="utf-8") as fh:
            file_cfg = json.load(fh)
    def pick(cli, key, default):
        return cli if cli not in (None, "", [], 0, 0.0) else file_cfg.get(key, default)
    if a.mode == "reverse" and not a.upstream and not file_cfg.get("upstream"):
        p.error("--upstream is required in reverse mode")
    return Config(
        host=pick(a.host, "host", a.host), port=a.port,
        mode=a.mode, upstream=a.upstream or file_cfg.get("upstream", ""),
        auth=a.auth or file_cfg.get("auth", ""), timeout=a.timeout,
        cache_ttl=a.cache_ttl or float(file_cfg.get("cache_ttl", 0)),
        rate_limit=a.rate_limit or int(file_cfg.get("rate_limit", 0)),
        block_hosts=tuple(a.block or file_cfg.get("block_hosts", [])),
        allow_hosts=tuple(a.allow or file_cfg.get("allow_hosts", [])),
        log_file=a.log_file or file_cfg.get("log_file", ""),
        log_format=a.log_format,
        watch_hosts=tuple(a.watch or file_cfg.get("watch_hosts", []))
        + (LUMI_WATCH_HOSTS if a.lumi or file_cfg.get("lumi") else ()),
        payload_capture=bool(a.payload_capture or file_cfg.get("payload_capture")),
        payload_allow_hosts=_csv(os.getenv("PAYLOAD_ALLOW_HOSTS", ""))
        or tuple(file_cfg.get("payload_allow_hosts", [])),
        payload_max_bytes=int(os.getenv("PAYLOAD_MAX_BYTES", "4096")),
        payload_aes_key=os.getenv("PAYLOAD_AES_KEY", ""),
        payload_aes_iv=os.getenv("PAYLOAD_AES_IV", ""),
        payload_lgeb=bool(a.payload_lgeb or file_cfg.get("payload_lgeb")),
        payload_lgeb_salt_hex=os.getenv("PAYLOAD_LGEB_SALT_HEX", ""),
        payload_lgeb_content_hash=os.getenv("PAYLOAD_LGEB_CONTENT_HASH", ""),
        intercept=bool(a.intercept or file_cfg.get("intercept")),
        intercept_allow_hosts=_csv(os.getenv("INTERCEPT_ALLOW_HOSTS", ""))
        or tuple(file_cfg.get("intercept_allow_hosts", [])),
        intercept_timeout=float(os.getenv("INTERCEPT_TIMEOUT", "30")),
    )


async def serve(cfg: Config) -> None:
    proxy = Proxy(cfg)
    server = await asyncio.start_server(proxy.handle, cfg.host, cfg.port)
    print(f"proxy-server listening on {cfg.host}:{cfg.port} mode={cfg.mode}"
          + (f" upstream={cfg.upstream}" if cfg.upstream else ""), flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None) -> None:
    try:
        asyncio.run(serve(config_from_env_and_args(argv)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
