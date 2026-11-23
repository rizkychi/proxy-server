"""Async HTTP forward proxy + reverse proxy.

Forward mode:
  - Plain HTTP requests are forwarded to the origin and relayed back.
  - CONNECT establishes a raw TCP tunnel (TLS passes through encrypted,
    the proxy never sees the plaintext) — unless MITM is enabled for
    that host (MITM_ALLOW_HOSTS, the operator's own servers only), in
    which case the proxy terminates TLS with a local CA so the
    decrypted traffic can be captured / intercepted like plain HTTP.
    MITM needs the third-party `cryptography` package; everything
    else is standard library only.

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
import ssl
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
    pac_hosts: tuple = ()          # hosts routed via this proxy in /proxy.pac
    public_host: str = ""          # public DNS/IP of B, used in the PAC file
    mitm: bool = False             # HTTPS termination, own hosts only
    mitm_allow_hosts: tuple = ()   # explicit allowlist for MITM
    mitm_ca_dir: str = ".proxy-ca"  # local CA cert/key + per-host leaf certs
    mitm_verify_upstream: bool = True  # verify A's real cert on the B->A leg

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


class MitmCA:
    """A local certificate authority for HTTPS termination (MITM).

    The CA is generated once into ``ca_dir`` (cert is downloadable from
    the dashboard so the operator can install it on their own phone;
    the key never leaves the server). Leaf certificates are minted per
    host and cached on disk. Needs the `cryptography` package; without
    it, ``ensure()`` returns False and MITM stays off.
    """

    def __init__(self, ca_dir: str):
        self.dir = ca_dir
        self.cert_path = os.path.join(ca_dir, "ca.crt.pem")
        self.key_path = os.path.join(ca_dir, "ca.key.pem")
        self._ready = False
        self._ca_cert = None
        self._ca_key = None
        self._ctx_cache: dict[str, ssl.SSLContext] = {}

    @staticmethod
    def available() -> bool:
        try:
            import cryptography  # noqa: F401
            return True
        except ImportError:
            return False

    def ensure(self) -> bool:
        if self._ready:
            return True
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            import datetime as _dt
        except ImportError:
            return False
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            if os.path.exists(self.cert_path) and \
                    os.path.exists(self.key_path):
                self._ca_cert = x509.load_pem_x509_certificate(
                    open(self.cert_path, "rb").read())
                self._ca_key = serialization.load_pem_private_key(
                    open(self.key_path, "rb").read(), None)
            else:
                self._ca_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048)
                name = x509.Name([x509.NameAttribute(
                    NameOID.COMMON_NAME, "proxy-server local CA")])
                now = _dt.datetime.now(_dt.timezone.utc)
                self._ca_cert = (
                    x509.CertificateBuilder()
                    .subject_name(name).issuer_name(name)
                    .public_key(self._ca_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - _dt.timedelta(days=1))
                    .not_valid_after(now + _dt.timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(
                        ca=True, path_length=0), critical=True)
                    .add_extension(x509.KeyUsage(
                        digital_signature=False, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True,
                        crl_sign=True, encipher_only=False,
                        decipher_only=False), critical=True)
                    .sign(self._ca_key, hashes.SHA256()))
                self._write_private(self.key_path, self._ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                with open(self.cert_path, "wb") as fh:
                    fh.write(self._ca_cert.public_bytes(
                        serialization.Encoding.PEM))
            self._ready = True
            return True
        except Exception as exc:
            print(f"mitm CA setup failed: {exc!r}", file=sys.stderr)
            return False

    @staticmethod
    def _write_private(path: str, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)

    def ca_pem(self) -> bytes:
        with open(self.cert_path, "rb") as fh:
            return fh.read()

    def fingerprint(self) -> str:
        if not self._ready:
            return ""
        from cryptography.hazmat.primitives import hashes
        fp = self._ca_cert.fingerprint(hashes.SHA256()).hex()
        return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))

    def server_context(self, host: str) -> ssl.SSLContext:
        """TLS server context presenting a leaf cert for ``host``."""
        if host in self._ctx_cache:
            return self._ctx_cache[host]
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        import datetime as _dt
        import ipaddress
        hosts_dir = os.path.join(self.dir, "hosts")
        os.makedirs(hosts_dir, mode=0o700, exist_ok=True)
        safe = "".join(ch if ch.isalnum() or ch in ".-" else "_"
                       for ch in host)
        leaf_path = os.path.join(hosts_dir, safe + ".pem")
        if not os.path.exists(leaf_path):
            key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
            try:
                san = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                san = x509.DNSName(host)
            now = _dt.datetime.now(_dt.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(
                    NameOID.COMMON_NAME, host)]))
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _dt.timedelta(days=1))
                .not_valid_after(now + _dt.timedelta(days=397))
                .add_extension(x509.SubjectAlternativeName([san]),
                               critical=False)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False,
                    decipher_only=False), critical=True)
                .sign(self._ca_key, hashes.SHA256()))
            blob = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()) + cert.public_bytes(
                    serialization.Encoding.PEM)
            self._write_private(leaf_path, blob)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(leaf_path)
        self._ctx_cache[host] = ctx
        return ctx


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
        self.ca = MitmCA(config.mitm_ca_dir)
        self._ca_ready = False
        self._ca_failed = False
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

            if target.split("?")[0] in ("/proxy.pac", "/__pac"):
                body = self.pac_text(headers.get("host", "")).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
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

            if target.split("?")[0] in ("/__ca", "/__ca.crt", "/ca.crt"):
                if self._maybe_ca():
                    body = self.ca.ca_pem()
                    writer.write(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Type: application/x-x509-ca-cert\r\n"
                                 b"Content-Disposition: attachment; "
                                 b"filename=\"proxy-server-ca.crt\"\r\n"
                                 b"Content-Length: " +
                                 str(len(body)).encode() +
                                 b"\r\nConnection: close\r\n\r\n" + body)
                    status = 200
                else:
                    body = json.dumps(
                        {"error": "MITM CA unavailable: enable MITM and "
                                  "install the cryptography package"}).encode()
                    writer.write(b"HTTP/1.1 404 Not Found\r\n"
                                 b"Content-Type: application/json\r\n"
                                 b"Content-Length: " +
                                 str(len(body)).encode() +
                                 b"\r\nConnection: close\r\n\r\n" + body)
                    status = 404
                await writer.drain()
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
                if self._mitm_enabled_for(target):
                    status = await self._mitm(reader, writer, target,
                                              sent, detail)
                else:
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

    def _maybe_ca(self) -> bool:
        """Lazily set up the MITM CA once; remember failures until the
        config changes so a missing `cryptography` install is not
        retried on every connection."""
        if self._ca_ready:
            return True
        if self._ca_failed:
            return False
        self._ca_ready = self.ca.ensure()
        if not self._ca_ready:
            self._ca_failed = True
        return self._ca_ready

    def _mitm_enabled_for(self, host: str) -> bool:
        if not self.cfg.mitm:
            return False
        if payload_forbidden(host):
            return False
        if not (self.cfg.mitm_allow_hosts
                and host_matches(host, self.cfg.mitm_allow_hosts)):
            return False
        return self._maybe_ca()

    async def _mitm(self, reader, writer, target: str, sent: list[int],
                    detail: dict) -> int:
        """Terminate TLS for one allowlisted host, then treat the
        decrypted stream as plain HTTP (capture / intercept apply).

        Two TLS legs: phone <-> B uses a leaf cert from B's local CA
        (the phone must trust that CA), B <-> A uses A's real cert.
        Requests are forwarded one at a time over a fresh upstream
        connection; the client leg stays open while responses are
        length- or chunk-framed.
        """
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)
        if self.cfg.mitm_verify_upstream:
            up_ctx = ssl.create_default_context()
        else:
            up_ctx = ssl._create_unverified_context()

        async def open_upstream():
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=up_ctx,
                                        server_hostname=host),
                self.cfg.timeout)

        try:
            up_reader, up_writer = await open_upstream()
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return 502

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        loop = asyncio.get_running_loop()
        new_reader = asyncio.StreamReader(limit=BUFFER * 4)
        protocol = asyncio.StreamReaderProtocol(new_reader)
        try:
            new_transport = await asyncio.wait_for(
                loop.start_tls(writer.transport, protocol,
                               self.ca.server_context(host),
                               server_side=True),
                self.cfg.timeout)
        except Exception as exc:
            print(f"mitm client TLS failed for {host}: {exc!r}",
                  file=sys.stderr)
            try:
                up_writer.close()
            except Exception:
                pass
            return 502
        tls_writer = asyncio.StreamWriter(new_transport, protocol,
                                          new_reader, loop)

        status = 200
        try:
            while True:
                try:
                    raw = await asyncio.wait_for(
                        read_head(new_reader), self.cfg.timeout)
                except Exception:
                    break
                if raw is None:
                    break
                first, headers, rest = parse_head(raw)
                parts = first.split(" ")
                if len(parts) < 2:
                    break
                path = parts[1]
                abs_target = path if path.startswith("http") else \
                    f"https://{host}:{port}" + \
                    (path if path.startswith("/") else "/" + path)
                req_detail: dict = {}
                status = await self._forward(
                    new_reader, tls_writer, first, headers, rest, None,
                    abs_target, sent, req_detail,
                    up_streams=(up_reader, up_writer),
                    close_client=False, default_port=443)
                if req_detail.get("payload"):
                    detail["payload"] = req_detail["payload"]
                if req_detail.get("response_framing") == "close" or \
                        status in (400, 502):
                    break
                try:
                    up_reader, up_writer = await open_upstream()
                except Exception:
                    break
        finally:
            for w in (tls_writer, up_writer):
                try:
                    w.close()
                except Exception:
                    pass
        return status

    def _intercept_enabled_for(self, host: str) -> bool:
        if not self.cfg.intercept:
            return False
        if payload_forbidden(host):
            return False
        return bool(self.cfg.intercept_allow_hosts
                    and host_matches(host, self.cfg.intercept_allow_hosts))

    def pac_text(self, request_host: str = "") -> str:
        """PAC file for phones: route PAC_HOSTS via B, everything else DIRECT.

        The proxy address advertised is PROXY_PUBLIC_HOST when set,
        otherwise the Host the client used to fetch this file.
        """
        advertised = self.cfg.public_host or request_host or \
            f"{self.cfg.host}:{self.cfg.port}"
        if ":" not in advertised:
            advertised = f"{advertised}:{self.cfg.port}"
        hosts = self.cfg.pac_hosts or self.cfg.payload_allow_hosts or \
            self.cfg.intercept_allow_hosts
        rules = []
        for pat in hosts:
            p = pat.lower()
            if p.startswith("*."):
                rules.append(
                    f'  if (dnsDomainIs(host, "{p[1:]}") || host == "{p[2:]}")'
                    f' return "PROXY {advertised}";')
            else:
                rules.append(
                    f'  if (host == "{p.split(":")[0]}")'
                    f' return "PROXY {advertised}";')
        body = "\n".join(rules) if rules else \
            f'  return "PROXY {advertised}";  // no PAC_HOSTS: route all via B'
        return ("function FindProxyForURL(url, host) {\n"
                "  host = host.toLowerCase();\n"
                f"{body}\n"
                '  return "DIRECT";\n'
                "}\n")

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
            "PAC_HOSTS": ",".join(c.pac_hosts),
            "PROXY_PUBLIC_HOST": c.public_host,
            "MITM": c.mitm,
            "MITM_ALLOW_HOSTS": ",".join(c.mitm_allow_hosts),
            "mitm_ca": {
                "ready": bool(self._ca_ready),
                "crypto_available": MitmCA.available(),
                "fingerprint": self.ca.fingerprint()
                if self._ca_ready else "",
                "download": "/__ca",
                "verify_upstream": c.mitm_verify_upstream,
            },
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
        set_csv("PAC_HOSTS", "pac_hosts")
        set_str("PROXY_PUBLIC_HOST", "public_host")
        if take("MITM") is not None:
            self._ca_failed = False  # retry CA setup after a toggle
        set_bool("MITM", "mitm")
        set_csv("MITM_ALLOW_HOSTS", "mitm_allow_hosts")
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
                       upstream_base, target, sent, detail=None,
                       up_streams=None, close_client=True,
                       default_port=80) -> int:
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
            host, port = u.hostname, u.port or default_port
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

        if up_streams is not None:
            up_reader, up_writer = up_streams
        else:
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
            if not intercept and close_client:
                try:
                    writer.close()
                except Exception:
                    pass

        response = b"".join(chunks)
        if detail is not None:
            resp_head = response.partition(b"\r\n\r\n")[0].lower()
            if b"content-length:" in resp_head or \
                    b"transfer-encoding: chunked" in resp_head:
                detail["response_framing"] = "length"
            else:
                detail["response_framing"] = "close"

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
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard proxy-server</title>
<style>
:root{--bg:#101318;--panel:#171b22;--panel2:#1e232c;--line:#2b313b;
--text:#eceef3;--muted:#a9b1bf;--accent:#f0b64a;--ok:#4cc38a;
--err:#f2707a;--info:#6cb2f5;--radius:8px}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
margin:0;background:var(--bg);color:var(--text);line-height:1.45}
header,main,footer{max-width:1180px;margin:0 auto;padding:0 24px}
header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;
align-items:flex-start;padding-top:22px}
h1{font-size:21px;margin:0}
h1 .sub{color:var(--muted);font-weight:500;font-size:15px}
h2{font-size:16px;margin:28px 0 10px}
.intro{margin:6px 0 0;max-width:64ch;color:var(--muted)}
.muted{color:var(--muted)} .small{font-size:12.5px}
.headctl{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);
border-radius:var(--radius);padding:12px 14px}
.card b{font-size:21px;display:block;font-variant-numeric:tabular-nums}
.panel{background:var(--panel);border:1px solid var(--line);
border-radius:var(--radius);padding:14px 16px;margin-top:10px}
table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;
font-size:13px;vertical-align:top}
th{color:var(--muted);font-weight:600}
.tscroll{overflow-x:auto}
tbody tr[data-i]{cursor:pointer}
tbody tr[data-i]:hover{background:var(--panel2)}
button,.btn{background:var(--panel2);color:var(--text);border:1px solid var(--line);
border-radius:var(--radius);padding:7px 12px;font-size:13.5px;cursor:pointer;
text-decoration:none;display:inline-block}
button:hover,.btn:hover{border-color:var(--muted)}
button.primary{background:var(--accent);border-color:var(--accent);
color:#1a1305;font-weight:600}
button.danger:hover{border-color:var(--err);color:var(--err)}
.chip.on{background:var(--accent);border-color:var(--accent);
color:#1a1305;font-weight:600}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;
border:1px solid var(--line);font-variant-numeric:tabular-nums;white-space:nowrap}
.pill.ok{color:var(--ok);border-color:var(--ok)}
.pill.err{color:var(--err);border-color:var(--err)}
.pill.warn{color:var(--accent);border-color:var(--accent)}
.pill.info{color:var(--info);border-color:var(--info)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:10px 0}
.toolbar input[type=search]{flex:1;min-width:200px}
input[type=text],input[type=password],input[type=search]{
background:var(--bg);color:var(--text);border:1px solid var(--line);
border-radius:var(--radius);padding:7px 10px;font-size:13.5px}
input[readonly]{width:100%}
.field{margin:12px 0}
.field label{display:block;font-weight:600;font-size:13.5px;margin-bottom:3px}
.field .help{color:var(--muted);font-size:12.5px}
.field input[type=text],.field input[type=password]{width:min(520px,100%)}
.check{display:flex;gap:9px;align-items:flex-start;cursor:pointer}
.check input{margin-top:2px;width:16px;height:16px;flex:none}
.check .help{display:block}
fieldset{border:1px solid var(--line);border-radius:var(--radius);
padding:6px 16px 14px;margin:14px 0}
legend{font-weight:700;padding:0 6px}
.errbar{background:#2b171a;border:1px solid var(--err);color:#ffd9dc;
border-radius:var(--radius);padding:10px 14px;margin-top:14px}
pre{background:var(--bg);border:1px solid var(--line);
border-radius:var(--radius);padding:8px;white-space:pre-wrap;
word-break:break-all;font-size:12px;max-height:260px;overflow:auto;margin:4px 0}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;
word-break:break-all}
ol.steps{margin:8px 0;padding-left:20px}
ol.steps li{margin:5px 0}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 28px}
@media(max-width:840px){.grid2{grid-template-columns:1fr}}
.watchname{color:var(--accent)}
.sr{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
footer{padding-bottom:28px;color:var(--muted);font-size:12.5px}
footer a{color:var(--info)}
@media (prefers-reduced-motion: reduce){*{transition:none!important}}
</style></head><body>
<header>
  <div>
    <h1>proxy-server <span class="sub">— dashboard operator</span></h1>
    <p class="intro">Pantau lalu lintas yang lewat proxy ini. Klik baris
    koneksi untuk detailnya. Payload hanya tampil untuk host milikmu yang
    ada di daftar capture; koneksi lain hanya metadata (host, status,
    ukuran, durasi).</p>
  </div>
  <div class="headctl">
    <span id="livePill" class="pill ok">Live — menyegarkan tiap 2 detik</span>
    <label class="check"><input type="checkbox" id="autoRefresh" checked>
    <span>Segarkan otomatis</span></label>
    <button type="button" id="btnRefresh">Segarkan sekarang</button>
  </div>
</header>
<main>
  <div id="errbar" class="errbar" hidden>Tidak bisa menghubungi server —
  menampilkan data terakhir yang berhasil dimuat. Akan dicoba lagi
  otomatis.</div>

  <section aria-labelledby="h-sum">
    <h2 id="h-sum">Ringkasan</h2>
    <div class="cards" id="cards"><p class="muted">Memuat data…</p></div>
  </section>

  <section aria-labelledby="h-traf">
    <h2 id="h-traf">Lalu lintas terbaru</h2>
    <div class="toolbar">
      <label class="sr" for="q">Cari berdasarkan host, method, atau status</label>
      <input id="q" type="search" placeholder="Cari host / method / status…">
      <div role="group" aria-label="Filter cepat">
        <button type="button" class="chip on" data-f="all">Semua</button>
        <button type="button" class="chip" data-f="watched">Dipantau</button>
        <button type="button" class="chip" data-f="errors">Error saja</button>
        <button type="button" class="chip" data-f="connect">CONNECT</button>
      </div>
    </div>
    <div id="detail" class="panel" hidden></div>
    <div class="tscroll"><table id="recent">
      <thead><tr><th>Waktu</th><th>Method</th><th>Host</th><th>Status</th>
      <th>Ukuran</th><th>Durasi</th><th>Keterangan</th></tr></thead>
      <tbody></tbody>
    </table></div>
    <p id="recentEmpty" class="muted" hidden>Belum ada lalu lintas yang
    cocok dengan filter ini. Arahkan HP ke proxy ini lalu buka sesuatu,
    atau longgarkan filternya.</p>
  </section>

  <section aria-labelledby="h-hold">
    <h2 id="h-hold">Ditahan — intercept</h2>
    <p class="muted small">Request dan response untuk host di daftar
    intercept berhenti di sini dulu. <b>Teruskan</b> = kirim seperti
    biasa. <b>Tolak</b> = putuskan (request ditolak 403, response
    digagalkan 502). Lewat batas timeout, yang ditahan diteruskan
    otomatis.</p>
    <div id="intercepts"><p class="muted">Tidak ada yang sedang ditahan.</p></div>
  </section>

  <section aria-labelledby="h-mitm">
    <h2 id="h-mitm">HTTPS — baca trafik terenkripsi (MITM)</h2>
    <div class="panel" id="mitmPanel"><p class="muted">Memuat status MITM…</p></div>
  </section>

  <div class="grid2">
    <section aria-labelledby="h-pac">
      <h2 id="h-pac">Sambungkan HP (PAC)</h2>
      <div class="panel">
        <label for="pacUrl"><b>URL PAC untuk Wi-Fi HP</b></label>
        <p class="help muted small">Di pengaturan Wi-Fi HP pilih proxy
        &ldquo;Auto&rdquo; lalu tempel URL ini. Hanya host di daftar PAC
        yang lewat proxy ini; sisanya langsung.</p>
        <input id="pacUrl" type="text" readonly value="">
        <p><button type="button" id="btnCopyPac">Salin URL PAC</button>
        <span id="pacMsg" class="muted small"></span></p>
        <p class="muted small">Atau proxy &ldquo;Manual&rdquo;: host =
        alamat proxy ini, port = port-nya. Manual mengarahkan semua
        trafik HP lewat sini.</p>
      </div>
    </section>
    <section aria-labelledby="h-watch">
      <h2 id="h-watch">Host yang dipantau &amp; tersibuk</h2>
      <div class="panel">
        <div id="watch"><p class="muted">Tidak ada watchlist — jalankan
        dengan <code>--lumi</code> atau <code>--watch HOST</code>.</p></div>
        <table id="watchTable"></table>
        <h3 class="small" style="margin:14px 0 4px">Host tersibuk</h3>
        <table id="tops"></table>
      </div>
    </section>
  </div>

  <section aria-labelledby="h-set">
    <h2 id="h-set">Pengaturan</h2>
    <div class="panel">
      <div id="settingsForm"><p class="muted">Memuat pengaturan…</p></div>
      <label class="check" style="margin-top:12px">
        <input type="checkbox" id="setPersist" checked>
        <span>Simpan juga ke .env
        <span class="help muted small" style="display:block">Kalau dicentang,
        pilihan di sini tetap berlaku setelah server di-restart.</span></span>
      </label>
      <p><button type="button" class="primary" id="btnSave">Simpan pengaturan</button>
      <span id="settingsMsg" class="muted" role="status"></span></p>
    </div>
  </section>
</main>
<footer>
  proxy-server dashboard · data mentah:
  <a href="/__stats">/__stats</a> · <a href="/__health">/__health</a> ·
  sertifikat CA: <a href="/__ca">/__ca</a>
</footer>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
function fmtBytes(n){ n = Number(n)||0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1).replace('.',',') + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(1).replace('.',',') + ' MB';
  return (n/1073741824).toFixed(2).replace('.',',') + ' GB'; }
function fmtMs(ms){ ms = Number(ms)||0;
  if (ms < 1000) return ms + ' ms';
  return (ms/1000).toFixed(1).replace('.',',') + ' dtk'; }
function fmtUptime(s){ s = Number(s)||0;
  if (s < 60) return s + ' dtk';
  if (s < 3600) return Math.floor(s/60) + ' mnt';
  if (s < 86400) return Math.floor(s/3600) + ' jam ' +
    Math.floor((s%3600)/60) + ' mnt';
  return Math.floor(s/86400) + ' hari'; }
function statusPill(st){ st = Number(st)||0;
  const cls = st>=500 ? 'err' : (st>=400 ? 'warn' : 'ok');
  return `<span class="pill ${cls}">${st===0 ? '—' : st}</span>`; }
window._recent = []; window._shown = []; window._filter = 'all';

function passesFilter(e){
  const f = window._filter;
  if (f === 'watched' && !e.watched) return false;
  if (f === 'errors' && !(Number(e.status) >= 400)) return false;
  if (f === 'connect' && String(e.method).toUpperCase() !== 'CONNECT')
    return false;
  const q = ($('q').value || '').trim().toLowerCase();
  if (q){
    const hay = (e.host + ' ' + e.method + ' ' + e.status + ' ' +
      e.target).toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function renderRecent(){
  const list = window._recent.slice(0,50).filter(passesFilter);
  window._shown = list;
  $('recent').querySelector('tbody').innerHTML = list.map((e,i)=>
    `<tr data-i="${i}" tabindex="0">` +
    `<td>${esc(e.time)}</td><td>${esc(e.method)}</td>` +
    `<td class="${e.watched?'watchname':''}">${esc(e.host)}</td>` +
    `<td>${statusPill(e.status)}</td><td>${fmtBytes(e.bytes)}</td>` +
    `<td>${fmtMs(e.duration_ms)}</td>` +
    `<td>${e.watched?'<span class="pill warn">dipantau</span>':''}` +
    `${e.payload?' <span class="pill info">payload ada</span>':''}</td></tr>`
  ).join('');
  $('recentEmpty').hidden = list.length > 0;
  $('recent').querySelectorAll('tbody tr[data-i]').forEach(tr=>{
    tr.addEventListener('click', ()=>showDetail(Number(tr.dataset.i)));
    tr.addEventListener('keydown', ev=>{
      if (ev.key==='Enter' || ev.key===' '){
        ev.preventDefault(); showDetail(Number(tr.dataset.i)); }});
  });
}

function renderIntercepts(pend){
  if (!pend.length){
    $('intercepts').innerHTML =
      '<p class="muted">Tidak ada yang sedang ditahan.</p>';
    return;
  }
  $('intercepts').innerHTML = pend.map(p=>{
    const phase = p.phase === 'request'
      ? 'Request — dari klien ke server (keluar)'
      : 'Response — dari server ke klien (masuk)';
    return `<div class="panel"><b>#${p.id} · ${esc(phase)}</b><br>` +
      `<span class="mono">${esc(p.method)} ${esc(p.host)}` +
      `${esc(p.target)}</span>` +
      (p.body ? `<pre>${esc(String(p.body.preview).slice(0,300))}</pre>` +
        `<span class="muted small">${esc(p.body.kind)} · ` +
        `${fmtBytes(p.body.size)}` +
        `${p.body.truncated?' · terpotong di tampilan':''}</span>` : '') +
      `<p><button type="button" class="primary" ` +
      `onclick="resolveIntercept(${p.id},'release')">Teruskan</button> ` +
      `<button type="button" class="danger" ` +
      `onclick="resolveIntercept(${p.id},'drop')">Tolak</button></p></div>`;
  }).join('');
}

async function tick(){
  try {
    const s = await (await fetch('/__stats')).json();
    $('errbar').hidden = true;
    $('livePill').className = 'pill ok';
    $('livePill').textContent = 'Live — menyegarkan tiap 2 detik';
    const c = [['Total request', s.requests], ['Error (5xx)', s.errors],
      ['Data terkirim', fmtBytes(s.bytes_sent)],
      ['Cache hit', s.cache_hits], ['Cache miss', s.cache_misses],
      ['Dibatasi (rate limit)', s.rate_limited], ['Diblokir', s.blocked],
      ['Server menyala sejak', fmtUptime(s.uptime_seconds)]];
    $('cards').innerHTML = c.map(x=>
      `<div class="card"><span class="muted small">${x[0]}</span>` +
      `<b>${x[1]}</b></div>`).join('');
    const w = s.watch || {};
    if ((w.patterns||[]).length){
      $('watch').innerHTML =
        `<p><span class="watchname"><b>${w.total_requests} request ` +
        `terpantau</b></span><br><span class="muted small">Pola: ` +
        `${esc(w.patterns.join(', '))}</span></p>`;
      $('watchTable').innerHTML =
        '<tr><th>Host terpantau</th><th>Request</th></tr>' +
        (w.hosts||[]).map(h=>
          `<tr><td class="watchname">${esc(h[0])}</td>` +
          `<td>${h[1]}</td></tr>`).join('');
    }
    window._recent = s.recent || [];
    renderRecent();
    const tops = s.top_hosts || [];
    $('tops').innerHTML = '<tr><th>Host</th><th>Request</th></tr>' +
      (tops.length ? tops.map(h=>
        `<tr><td>${esc(h[0])}</td><td>${h[1]}</td></tr>`).join('')
        : '<tr><td class="muted">belum ada data</td><td></td></tr>');
  } catch(e) {
    $('errbar').hidden = false;
    $('livePill').className = 'pill err';
    $('livePill').textContent = 'Terputus — mencoba lagi…';
  }
  try {
    const ij = await (await fetch('/__intercepts')).json();
    renderIntercepts(ij.pending || []);
  } catch(e) {}
}
const FIELDS = [
  {group:'Capture payload — lihat isi lalu lintas host milikmu'},
  {k:'PAYLOAD_CAPTURE', t:'bool', label:'Rekam payload',
   help:'Isi request/response untuk host di daftar bawah ditampilkan di detail koneksi.'},
  {k:'PAYLOAD_ALLOW_HOSTS', t:'text', label:'Host yang direkam',
   help:'Pisahkan dengan koma. Boleh wildcard, contoh: api.serverku.com, *.serverku.com'},
  {k:'PAYLOAD_MAX_BYTES', t:'text', label:'Batas ukuran tampilan (byte)',
   help:'Payload yang lebih besar dipotong di tampilan saja, bukan di lalu lintasnya.'},
  {k:'PAYLOAD_LGEB', t:'bool', label:'Pembaca bundle LGEB',
   help:'Coba dekripsi payload berformat LGEB (header LGEB + AES) memakai salt server A milikmu.'},
  {k:'PAYLOAD_LGEB_CONTENT_HASH', t:'text', label:'Content hash LGEB (opsional)',
   help:'Kosongkan untuk mengambil hash dari nama file bundle.'},
  {k:'PAYLOAD_LGEB_SALT_HEX', t:'secret', label:'Salt LGEB server A',
   help:'Rahasia. Kosongkan untuk mempertahankan yang sudah tersimpan.'},
  {k:'PAYLOAD_AES_KEY', t:'secret', label:'Kunci AES payload (opsional)',
   help:'Untuk payload AES-128-CBC biasa. Rahasia, hanya bisa diisi.'},
  {k:'PAYLOAD_AES_IV', t:'secret', label:'IV AES payload (opsional)',
   help:'Pasangan kunci di atas. Rahasia, hanya bisa diisi.'},
  {group:'Intercept — tahan dulu, putuskan kemudian'},
  {k:'INTERCEPT', t:'bool', label:'Aktifkan intercept',
   help:'Request dan response untuk host di daftar bawah ditahan sampai kamu meneruskan atau menolaknya di panel Ditahan.'},
  {k:'INTERCEPT_ALLOW_HOSTS', t:'text', label:'Host yang ditahan',
   help:'Pisahkan dengan koma. Boleh wildcard.'},
  {k:'INTERCEPT_TIMEOUT', t:'text', label:'Batas waktu menahan (detik)',
   help:'Lewat waktu ini, yang ditahan diteruskan otomatis supaya trafikmu tidak menggantung.'},
  {group:'HTTPS (MITM) — baca trafik terenkripsi host milikmu'},
  {k:'MITM', t:'bool', label:'Aktifkan MITM',
   help:'Proxy mengakhiri TLS untuk host di daftar bawah memakai CA lokal, sehingga payload HTTPS terbaca seperti HTTP. HP harus mempercayai CA-nya — lihat panel HTTPS di atas.'},
  {k:'MITM_ALLOW_HOSTS', t:'text', label:'Host untuk MITM',
   help:'Pisahkan dengan koma. Boleh wildcard. Hanya host milikmu.'},
  {group:'Umum'},
  {k:'PAC_HOSTS', t:'text', label:'Host lewat proxy di file PAC',
   help:'Host yang diarahkan HP ke proxy ini; sisanya langsung (DIRECT).'},
  {k:'PROXY_PUBLIC_HOST', t:'text', label:'Alamat publik proxy ini',
   help:'Domain/IP publik + port, dipakai di file PAC. Contoh: 168.107.75.12:8089'},
  {k:'PROXY_CACHE_TTL', t:'text', label:'Cache response GET (detik)',
   help:'0 = mati. Response GET disimpan sebentar untuk request berulang.'},
  {k:'PROXY_RATE_LIMIT', t:'text', label:'Batas request per menit per IP',
   help:'0 = mati.'},
  {k:'PROXY_LOG_FORMAT', t:'text', label:'Format log',
   help:'text atau json.'},
];
window._cfg = null;

function renderMitm(){
  const el = $('mitmPanel');
  const c = window._cfg;
  if (!c){ el.innerHTML = '<p class="muted">Memuat status MITM…</p>'; return; }
  const ca = c.mitm_ca || {};
  let h = `<p>Status: ${c.MITM
    ? '<span class="pill ok">Aktif</span>'
    : '<span class="pill warn">Mati</span>'} · CA: ${ca.ready
    ? '<span class="pill ok">Siap</span>'
    : (ca.crypto_available
      ? '<span class="pill warn">Dibuat saat MITM pertama kali aktif</span>'
      : '<span class="pill err">Butuh paket cryptography di server</span>')}</p>`;
  h += `<p class="muted small">Host yang di-MITM: <span class="mono">` +
    `${esc(c.MITM_ALLOW_HOSTS || '(belum ada — isi di Pengaturan)')}</span>` +
    ` · Verifikasi sertifikat asli server tujuan: ` +
    `${ca.verify_upstream ? 'ya' : 'tidak (MITM_VERIFY_UPSTREAM=0)'}</p>`;
  if (ca.fingerprint)
    h += `<p class="muted small">Fingerprint SHA-256 CA — samakan dengan ` +
      `yang tampil di HP saat memasang sertifikat:<br>` +
      `<span class="mono">${esc(ca.fingerprint)}</span></p>`;
  h += `<p><a class="btn primary" href="/__ca" download>Unduh sertifikat ` +
    `CA (.crt)</a></p>`;
  h += `<b>Pasang di HP, sekali saja:</b><ol class="steps">` +
    `<li>Unduh file CA dari tombol di atas.</li>` +
    `<li><b>Android:</b> Pengaturan → Keamanan → Pasang sertifikat → ` +
    `Sertifikat CA → pilih file tadi.</li>` +
    `<li><b>iPhone:</b> buka file-nya untuk memasang profil, lalu ` +
    `Pengaturan → Umum → Tentang → Pengaturan Kepercayaan Sertifikat → ` +
    `aktifkan untuk CA ini.</li>` +
    `<li>Nyalakan MITM di Pengaturan dan isi host server milikmu. ` +
    `Setelah itu, koneksi HTTPS ke host tersebut muncul sebagai request ` +
    `yang terbaca — bukan lagi CONNECT buta.</li></ol>`;
  h += `<p class="muted small">Aplikasi yang memakai certificate pinning ` +
    `tetap menolak sertifikat ini; untuk aplikasi milikmu, atur dari sisi ` +
    `aplikasinya. Yang diunduh hanya sertifikat publik CA — kunci ` +
    `privatnya tidak pernah meninggalkan server.</p>`;
  el.innerHTML = h;
}

async function loadSettings(){
  try {
    const c = await (await fetch('/__config')).json();
    window._cfg = c;
    let h = '', open = false;
    for (const f of FIELDS){
      if (f.group){
        if (open) h += '</fieldset>';
        h += `<fieldset><legend>${esc(f.group)}</legend>`;
        open = true;
        continue;
      }
      if (f.t === 'bool'){
        h += `<div class="field"><label class="check">` +
          `<input type="checkbox" id="cfg_${f.k}" ${c[f.k]?'checked':''}>` +
          `<span>${esc(f.label)}<span class="help" style="display:block">` +
          `${esc(f.help)}</span></span></label></div>`;
      } else if (f.t === 'secret'){
        const isSet = (c.secrets_set || {})[f.k];
        h += `<div class="field"><label for="cfg_${f.k}">` +
          `${esc(f.label)}</label>` +
          `<input type="password" id="cfg_${f.k}" autocomplete="off" ` +
          `placeholder="${isSet ? 'sudah tersimpan — kosongkan untuk mempertahankan' : 'belum diisi'}">` +
          `<div class="help">${esc(f.help)}</div></div>`;
      } else {
        h += `<div class="field"><label for="cfg_${f.k}">` +
          `${esc(f.label)}</label>` +
          `<input type="text" id="cfg_${f.k}" ` +
          `value="${esc(c[f.k] ?? '')}">` +
          `<div class="help">${esc(f.help)}</div></div>`;
      }
    }
    if (open) h += '</fieldset>';
    const r = c.restart_only || {};
    h += `<p class="muted small">Pengaturan bind — tersimpan ke .env, ` +
      `berlaku setelah restart: PROXY_HOST=${esc(r.PROXY_HOST)} · ` +
      `PROXY_PORT=${esc(r.PROXY_PORT)} · PROXY_MODE=${esc(r.PROXY_MODE)}` +
      (r.PROXY_UPSTREAM ? ` · PROXY_UPSTREAM=${esc(r.PROXY_UPSTREAM)}` : '') +
      `</p>`;
    $('settingsForm').innerHTML = h;
  } catch(e) {
    $('settingsForm').innerHTML =
      '<p class="muted">Gagal memuat pengaturan — server tidak menjawab.</p>';
  }
  renderMitm();
}

window.saveSettings = async function(){
  const body = new URLSearchParams();
  for (const f of FIELDS){
    if (!f.k) continue;
    const el = $('cfg_' + f.k);
    if (!el) continue;
    if (f.t === 'bool') body.set(f.k, el.checked ? '1' : '0');
    else if (f.t === 'secret'){ if (el.value) body.set(f.k, el.value); }
    else body.set(f.k, el.value);
  }
  body.set('PERSIST', $('setPersist').checked ? '1' : '0');
  const msg = $('settingsMsg');
  try {
    const r = await (await fetch('/__config', {method:'POST', body})).json();
    msg.textContent = 'Tersimpan — ' + (r.applied||[]).length +
      ' pengaturan berlaku sekarang' +
      (r.persisted ? ', ditulis ke .env' : ', hanya sesi ini') +
      ((r.restart_required_for||[]).length
        ? '. Perlu restart untuk: ' + r.restart_required_for.join(', ')
        : '') + '.';
  } catch(e) {
    msg.textContent = 'Gagal menyimpan — server tidak menjawab.';
  }
  loadSettings();
};
window.resolveIntercept = async function(id, action){
  await fetch('/__intercept/' + action + '?id=' + id);
  tick();
};

window.showDetail = function(i){
  const e = (window._shown||[])[i]; if(!e) return;
  const rows = [['Nomor koneksi', '#' + e.id], ['Waktu', e.time],
    ['Klien', e.peer], ['Method', e.method], ['Host', e.host],
    ['Target / path', e.target], ['Status', e.status],
    ['Ukuran (sisi request)', fmtBytes(e.bytes)],
    ['Durasi', fmtMs(e.duration_ms)],
    ['Di watchlist', e.watched ? 'ya' : 'tidak']];
  let h = `<div style="display:flex;justify-content:space-between;` +
    `align-items:center;gap:10px"><b>Detail koneksi #${e.id}</b>` +
    `<button type="button" id="btnCloseDetail">Tutup</button></div>` +
    `<table>` + rows.map(r=>
      `<tr><td class="muted" style="width:190px">${r[0]}</td>` +
      `<td>${esc(r[1])}</td></tr>`).join('') + `</table>`;
  if (e.payload){
    const names = {request:'Payload request', response:'Payload response',
      request_decrypted:'Request terdekripsi (AES)',
      response_decrypted:'Response terdekripsi (AES)',
      request_lgeb:'Request terdekripsi (LGEB)',
      response_lgeb:'Response terdekripsi (LGEB)'};
    for (const k of Object.keys(names)){
      const v = e.payload[k];
      if (v) h += `<h3 class="small" style="margin:12px 0 2px">` +
        `${names[k]} <span class="muted">(${esc(v.kind)}, ` +
        `${fmtBytes(v.size)}${v.truncated?', terpotong di tampilan':''})` +
        `</span></h3><pre>${esc(v.preview)}</pre>`;
    }
  } else if (String(e.method).toUpperCase() === 'CONNECT'){
    h += `<p class="muted">Payload tidak ada: ini terowongan CONNECT ` +
      `(HTTPS) — isinya terenkripsi ujung-ke-ujung antara HP dan server ` +
      `tujuan, proxy hanya meneruskan. Supaya terbaca, aktifkan MITM ` +
      `untuk host ini di Pengaturan dan pasang sertifikat CA di HP.</p>`;
  } else {
    h += `<p class="muted">Payload tidak direkam untuk host ini. ` +
      `Nyalakan "Rekam payload" di Pengaturan dan masukkan host-nya ke ` +
      `daftar host yang direkam.</p>`;
  }
  const d = $('detail');
  d.innerHTML = h;
  d.hidden = false;
  $('btnCloseDetail').addEventListener('click', ()=>{ d.hidden = true; });
  d.scrollIntoView({block:'nearest'});
};

document.querySelectorAll('.chip').forEach(ch=>
  ch.addEventListener('click', ()=>{
    document.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));
    ch.classList.add('on');
    window._filter = ch.dataset.f;
    renderRecent();
  }));
$('q').addEventListener('input', renderRecent);
$('btnRefresh').addEventListener('click', tick);
$('btnSave').addEventListener('click', ()=>window.saveSettings());
$('pacUrl').value = location.origin + '/proxy.pac';
$('btnCopyPac').addEventListener('click', async ()=>{
  try { await navigator.clipboard.writeText($('pacUrl').value); }
  catch(e){ $('pacUrl').select(); document.execCommand('copy'); }
  $('pacMsg').textContent = 'Tersalin — tempel di pengaturan Wi-Fi HP.';
});
document.addEventListener('keydown', ev=>{
  if (ev.key === 'Escape') $('detail').hidden = true;
});
setInterval(()=>{ if ($('autoRefresh').checked) tick(); }, 2000);
loadSettings();
tick();
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
    p.add_argument("--mitm", action="store_true",
                   default=os.getenv("MITM", "") in ("1", "true", "yes"),
                   help="terminate TLS for MITM_ALLOW_HOSTS with a local "
                        "CA so HTTPS traffic can be captured/intercepted "
                        "(needs the cryptography package)")
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
        pac_hosts=_csv(os.getenv("PAC_HOSTS", ""))
        or tuple(file_cfg.get("pac_hosts", [])),
        public_host=os.getenv("PROXY_PUBLIC_HOST", "")
        or file_cfg.get("public_host", ""),
        mitm=bool(a.mitm or file_cfg.get("mitm")),
        mitm_allow_hosts=_csv(os.getenv("MITM_ALLOW_HOSTS", ""))
        or tuple(file_cfg.get("mitm_allow_hosts", [])),
        mitm_ca_dir=os.getenv("MITM_CA_DIR", "")
        or file_cfg.get("mitm_ca_dir", ".proxy-ca"),
        mitm_verify_upstream=os.getenv("MITM_VERIFY_UPSTREAM", "1")
        not in ("0", "false", "no"),
    )


async def serve(cfg: Config) -> None:
    proxy = Proxy(cfg)
    server = await asyncio.start_server(proxy.handle, cfg.host, cfg.port)
    print(f"proxy-server listening on {cfg.host}:{cfg.port} mode={cfg.mode}"
          + (f" upstream={cfg.upstream}" if cfg.upstream else ""), flush=True)
    if cfg.mitm:
        if proxy._maybe_ca():
            print(f"mitm on for {list(cfg.mitm_allow_hosts)}; "
                  f"CA cert: http://{cfg.host}:{cfg.port}/__ca "
                  f"(fingerprint {proxy.ca.fingerprint()})", flush=True)
        else:
            print("mitm requested but unavailable: install the "
                  "cryptography package (pip install cryptography)",
                  flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None) -> None:
    try:
        asyncio.run(serve(config_from_env_and_args(argv)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
