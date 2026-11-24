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
import hmac
import html
import json
from collections import Counter, deque
import os
import secrets
import ssl
import sys
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, urlsplit

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
    auth: str = ""                 # proxy Basic auth: "user:password" or ""
    dashboard_auth: str = ""       # dashboard login: "user:password" or ""
    dashboard_session_ttl: int = 43200  # dashboard session lifetime, seconds
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
        self.dashboard_sessions: dict[str, dict] = {}
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

    # ----- dashboard login / session helpers -----
    async def _send(self, writer: asyncio.StreamWriter, status: int,
                    content_type: str, body: bytes,
                    extra_headers: tuple[str, ...] = ()) -> None:
        reason = {200: "OK", 302: "Found", 400: "Bad Request",
                  401: "Unauthorized", 403: "Forbidden",
                  404: "Not Found"}.get(status, "OK")
        head = (f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n")
        for header in extra_headers:
            head += header + "\r\n"
        writer.write(head.encode() + b"\r\n" + body)
        await writer.drain()

    async def _send_json(self, writer: asyncio.StreamWriter, obj: dict,
                         status: int = 200,
                         extra_headers: tuple[str, ...] = ()) -> None:
        await self._send(writer, status, "application/json",
                         json.dumps(obj).encode(), extra_headers)

    async def _redirect(self, writer: asyncio.StreamWriter, location: str,
                        extra_headers: tuple[str, ...] = ()) -> None:
        await self._send(writer, 302, "text/plain; charset=utf-8", b"",
                         (f"Location: {location}",) + extra_headers)

    async def _read_body(self, reader: asyncio.StreamReader,
                         headers: dict[str, str], rest: bytes) -> bytes:
        body = rest
        try:
            remaining = int(headers.get("content-length", "0")) - len(rest)
        except ValueError:
            remaining = 0
        while remaining > 0:
            chunk = await reader.read(min(BUFFER, remaining))
            if not chunk:
                break
            body += chunk
            remaining -= len(chunk)
        return body

    def _cookie_value(self, headers: dict[str, str], name: str) -> str:
        for part in headers.get("cookie", "").split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                if key.strip() == name:
                    return value.strip()
        return ""

    def _dashboard_auth_enabled(self) -> bool:
        return bool(self.cfg.dashboard_auth and ":" in self.cfg.dashboard_auth)

    def _dashboard_username(self) -> str:
        if self._dashboard_auth_enabled():
            return self.cfg.dashboard_auth.split(":", 1)[0] or "Operator"
        return "Operator"

    def _valid_dashboard_credentials(self, username: str,
                                     password: str) -> bool:
        if not self._dashboard_auth_enabled():
            return False
        expected_user, expected_pass = self.cfg.dashboard_auth.split(":", 1)
        return hmac.compare_digest(username, expected_user) and \
            hmac.compare_digest(password, expected_pass)

    def _dashboard_session_user(self, headers: dict[str, str]) -> str | None:
        if not self._dashboard_auth_enabled():
            return self._dashboard_username()
        token = self._cookie_value(headers, "proxy_dashboard_session")
        session = self.dashboard_sessions.get(token)
        if not session:
            return None
        if time.time() > session["expires"]:
            self.dashboard_sessions.pop(token, None)
            return None
        return str(session["user"])

    def _create_dashboard_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        ttl = max(300, int(self.cfg.dashboard_session_ttl or 43200))
        self.dashboard_sessions[token] = {
            "user": username, "expires": time.time() + ttl}
        return token

    def _dashboard_cookie(self, token: str) -> str:
        ttl = max(300, int(self.cfg.dashboard_session_ttl or 43200))
        return (f"proxy_dashboard_session={token}; Path=/; HttpOnly; "
                f"SameSite=Lax; Max-Age={ttl}")

    def _clear_dashboard_cookie(self) -> str:
        return ("proxy_dashboard_session=; Path=/; HttpOnly; "
                "SameSite=Lax; Max-Age=0")

    async def _require_dashboard(self, writer: asyncio.StreamWriter,
                                 headers: dict[str, str], api: bool,
                                 next_path: str = "/__dashboard") -> bool:
        if self._dashboard_session_user(headers):
            return True
        if api:
            await self._send_json(
                writer, {"ok": False, "error": "login required",
                         "login": "/__login"}, status=401)
        else:
            await self._redirect(
                writer, "/__login?next=" + quote(next_path, safe="/"))
        return False

    def _safe_next(self, value: str) -> str:
        if value.startswith("/") and not value.startswith("//"):
            return value
        return "/__dashboard"

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

            path_only = target.split("?")[0]

            if path_only in ("/__login", "/login"):
                query = parse_qs(urlsplit(target).query)
                next_path = self._safe_next(
                    query.get("next", ["/__dashboard"])[0])
                if method.upper() == "POST":
                    body_bytes = await self._read_body(reader, headers, rest)
                    form = parse_qs(body_bytes.decode("utf-8", "replace"))
                    next_path = self._safe_next(
                        form.get("next", [next_path])[0])
                    if not self._dashboard_auth_enabled():
                        await self._redirect(writer, next_path)
                        status = 302
                        return
                    username = form.get("username", [""])[0]
                    password = form.get("password", [""])[0]
                    if self._valid_dashboard_credentials(username, password):
                        token = self._create_dashboard_session(username)
                        await self._redirect(
                            writer, next_path,
                            ("Set-Cookie: " + self._dashboard_cookie(token),))
                        status = 302
                        return
                    await self._redirect(
                        writer, "/__login?error=1&next=" +
                        quote(next_path, safe="/"))
                    status = 302
                    return
                if self._dashboard_auth_enabled() and \
                        self._dashboard_session_user(headers):
                    await self._redirect(writer, next_path)
                    status = 302
                    return
                body = render_login_html(
                    self._dashboard_auth_enabled(),
                    error=query.get("error", [""])[0] == "1",
                    next_path=next_path).encode()
                await self._send(writer, 200, "text/html; charset=utf-8",
                                 body)
                status = 200
                return

            if path_only in ("/__logout", "/logout"):
                token = self._cookie_value(
                    headers, "proxy_dashboard_session")
                self.dashboard_sessions.pop(token, None)
                clear = "Set-Cookie: " + self._clear_dashboard_cookie()
                if method.upper() == "POST":
                    await self._send_json(
                        writer, {"ok": True,
                                 "auth_enabled":
                                 self._dashboard_auth_enabled()},
                        extra_headers=(clear,))
                    status = 200
                else:
                    await self._redirect(writer, "/__login", (clear,))
                    status = 302
                return

            if path_only in ("/__session", "/session"):
                user = self._dashboard_session_user(headers)
                await self._send_json(writer, {
                    "auth_enabled": self._dashboard_auth_enabled(),
                    "authenticated": bool(user), "user": user or "",
                    "login": "/__login", "logout": "/__logout"})
                status = 200
                return

            if target in ("/__dashboard", "/dashboard"):
                if not await self._require_dashboard(
                        writer, headers, api=False,
                        next_path="/__dashboard"):
                    status = 302
                    return
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
                if not await self._require_dashboard(writer, headers,
                                                     api=True):
                    status = 401
                    return
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
                if not await self._require_dashboard(writer, headers,
                                                     api=True):
                    status = 401
                    return
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
                if not await self._require_dashboard(writer, headers,
                                                     api=True):
                    status = 401
                    return
                action = "release" if "/release" in target else "drop"
                q = parse_qs(urlsplit(target).query)
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
                if not await self._require_dashboard(writer, headers,
                                                     api=True):
                    status = 401
                    return
                body = json.dumps(self.stats.snapshot()).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                status = 200
                return

            if target.split("?")[0] in ("/__ca", "/__ca.crt", "/ca.crt"):
                if not await self._require_dashboard(writer, headers,
                                                     api=True):
                    status = 401
                    return
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
            "dashboard_auth": {
                "enabled": self._dashboard_auth_enabled(),
                "user": self._dashboard_username(),
                "session_ttl": c.dashboard_session_ttl,
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

LOGIN_HTML = """<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login Dashboard proxy-server</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--color-accent:#4F46E5;--color-on-accent:#FFFFFF;
--color-background:#F6F7F9;--color-foreground:#1E293B;
--color-card:#FFFFFF;--color-muted-foreground:#5B6B82;
--color-border:#CBD5E1;--color-secondary:#E2E8F0;
--color-destructive:#DC2626;
--font-heading:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--font-body:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}
body{font-family:var(--font-body);margin:0;min-height:100vh;
background:var(--color-background);color:var(--color-foreground);
display:flex;align-items:center;justify-content:center;padding:20px}
.login-card{width:min(400px,100%);background:var(--color-card);
border:1px solid var(--color-secondary);border-radius:16px;
padding:28px;box-shadow:0 12px 32px rgba(15,23,42,.10)}
.logo{width:44px;height:44px;border-radius:12px;background:var(--color-accent);
color:var(--color-on-accent);display:flex;align-items:center;
justify-content:center;font-family:var(--font-heading);font-weight:800;
font-size:17px;margin-bottom:14px}
h1{font-family:var(--font-heading);font-size:20px;margin:0 0 4px}
.sub{color:var(--color-muted-foreground);font-size:13.5px;margin:0 0 18px}
label{display:block;font-weight:600;font-size:13.5px;margin:13px 0 5px}
input{width:100%;background:var(--color-card);
color:var(--color-foreground);border:1px solid var(--color-border);
border-radius:8px;padding:10px 12px;font-size:14px}
input:focus{border-color:var(--color-accent);outline:none;
box-shadow:0 0 0 3px rgba(79,70,229,.18)}
button{width:100%;margin-top:18px;background:var(--color-accent);
border:1px solid var(--color-accent);color:var(--color-on-accent);
font-weight:700;border-radius:8px;padding:11px;font-size:14.5px;cursor:pointer}
button:hover{opacity:.92}
.error{background:rgba(220,38,38,.06);border:1px solid var(--color-destructive);
color:#B91C1C;border-radius:8px;padding:10px 13px;font-size:13.5px}
.note{color:var(--color-muted-foreground);font-size:12.5px;margin-top:16px}
code{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:12px}
</style></head><body>
<main class="login-card">
  <div class="logo" aria-hidden="true">PS</div>
  <h1>proxy-server</h1>
  <p class="sub">Masuk ke dashboard admin untuk melanjutkan.</p>
  {{ERROR_BLOCK}}
  <form method="post" action="/__login">
    <input type="hidden" name="next" value="{{NEXT}}">
    <label for="username">Username</label>
    <input id="username" name="username" type="text"
      autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password"
      autocomplete="current-password" required>
    <button type="submit">Masuk</button>
  </form>
  <p class="note">{{AUTH_NOTE}}</p>
</main>
</body></html>
"""


def render_login_html(auth_enabled: bool, error: bool = False,
                      next_path: str = "/__dashboard") -> str:
    if error:
        error_block = ('<p class="error" role="alert">Username atau '
                       'password salah. Coba lagi.</p>')
    else:
        error_block = ""
    if auth_enabled:
        note = ("Sesi login tersimpan sebagai cookie di browser ini. "
                "Keluar dari menu pengguna di kanan atas dashboard.")
    else:
        note = ("Login dashboard belum diaktifkan di server ini, jadi "
                "dashboard masih terbuka tanpa login. Untuk "
                "mengaktifkannya, isi <code>DASHBOARD_AUTH="
                "user:password</code> di file .env server lalu restart. "
                "Form ini akan langsung membawamu ke dashboard.")
    return (LOGIN_HTML.replace("{{ERROR_BLOCK}}", error_block)
            .replace("{{AUTH_NOTE}}", note)
            .replace("{{NEXT}}", html.escape(next_path, quote=True)))


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard proxy-server</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--color-primary:#FFFFFF;--color-secondary:#E2E8F0;
--color-accent:#4F46E5;--color-on-accent:#FFFFFF;
--color-background:#F6F7F9;--color-foreground:#1E293B;
--color-card:#FFFFFF;--color-muted:#EEF2F7;
--color-muted-foreground:#5B6B82;--color-border:#CBD5E1;
--color-destructive:#DC2626;--ok:#15803D;--warn:#B45309;--info:#0369A1;
--font-heading:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--font-body:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--font-mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--space-xs:2px;--space-sm:4px;--space-md:8px;--space-lg:12px;
--space-xl:16px;--space-2xl:24px;--space-3xl:32px;
--shadow-sm:0 1px 2px rgba(15,23,42,.05),0 1px 3px rgba(15,23,42,.06)}
*{box-sizing:border-box}
body{font-family:var(--font-body);margin:0;
background:var(--color-background);color:var(--color-foreground);
line-height:1.5;font-size:14px}
button,.btn,.navlink,label.check{cursor:pointer}
.app{display:flex;min-height:100vh;align-items:stretch}
/* ---------- sidebar ---------- */
.sidebar{width:264px;flex:none;background:var(--color-primary);
border-right:1px solid var(--color-secondary);display:flex;
flex-direction:column;position:sticky;top:0;height:100vh;
padding:var(--space-xl) var(--space-lg);z-index:40}
.brand{display:flex;gap:12px;align-items:center;
padding:var(--space-sm) var(--space-md) var(--space-xl);
border-bottom:1px solid var(--color-secondary)}
.brand .logo{width:38px;height:38px;flex:none;border-radius:10px;
background:var(--color-accent);color:var(--color-on-accent);
display:flex;align-items:center;justify-content:center;
font-family:var(--font-heading);font-weight:700;font-size:14px}
.brand .name{font-family:var(--font-heading);font-size:16.5px;
font-weight:600;letter-spacing:-.01em;line-height:1.2}
.brand .name .dot{color:var(--color-accent)}
.brand .tag{color:var(--color-muted-foreground);font-size:12px;
margin-top:1px}
.sidebar nav{display:flex;flex-direction:column;gap:var(--space-xl);
margin-top:var(--space-xl);overflow-y:auto}
.navgroup{display:flex;flex-direction:column;gap:var(--space-xs)}
.navlabel{color:var(--color-muted-foreground);font-size:11px;
font-weight:700;letter-spacing:.08em;text-transform:uppercase;
margin:0 var(--space-md) var(--space-sm)}
.navlink{display:flex;align-items:center;gap:10px;
padding:9px var(--space-lg);color:var(--color-foreground);
text-decoration:none;font-size:14px;border-radius:8px;position:relative;
transition:background 180ms ease}
.navlink svg{flex:none;opacity:.7}
.navlink:hover{background:var(--color-muted)}
.navlink.active{background:var(--color-muted);font-weight:600}
.navlink.active svg{opacity:1;color:var(--color-accent)}
.navlink .badge{margin-left:auto;background:var(--color-accent);
color:var(--color-on-accent);font-size:11.5px;font-weight:700;
border-radius:6px;padding:0 6px;line-height:18px}
.sidefoot{margin-top:auto;padding-top:var(--space-lg)}
.usercard{display:flex;gap:10px;align-items:center;background:var(--color-muted);
border:1px solid var(--color-secondary);border-radius:12px;
padding:10px 12px}
.avatar{width:34px;height:34px;flex:none;border-radius:50%;
background:var(--color-accent);color:var(--color-on-accent);
display:flex;align-items:center;justify-content:center;
font-weight:700;font-size:13px;font-family:var(--font-heading)}
.usercard .meta{min-width:0;flex:1}
.usercard .meta b{display:block;font-size:13.5px;line-height:1.25;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.usercard .meta span{color:var(--color-muted-foreground);font-size:12px}
.iconbtn{background:transparent;border:1px solid transparent;
color:var(--color-muted-foreground);border-radius:8px;padding:7px;
display:inline-flex;align-items:center;justify-content:center}
.iconbtn:hover{color:var(--color-foreground);border-color:var(--color-border);
background:var(--color-muted)}
.sidever{color:var(--color-muted-foreground);font-size:11.5px;
text-align:center;margin-top:10px}
.scrim{display:none}
/* ---------- content + topbar ---------- */
.content{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{border-bottom:1px solid var(--color-secondary);
padding:10px 28px;display:flex;justify-content:space-between;
gap:14px;align-items:center;position:sticky;top:0;z-index:30;
background:rgba(255,255,255,.92)}
.topbar .left{display:flex;gap:12px;align-items:center;min-width:0}
.crumb{color:var(--color-muted-foreground);font-size:12px}
.topbar h1{font-family:var(--font-heading);font-size:18px;margin:0;
font-weight:600;letter-spacing:-.01em;line-height:1.25}
.topbar .sub{color:var(--color-muted-foreground);font-size:12.5px}
.headctl{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.globalsearch{display:flex;align-items:center}
.globalsearch input{width:210px}
.live{display:inline-flex;align-items:center;gap:8px;font-size:13px;
color:var(--color-muted-foreground)}
.live .sq{width:8px;height:8px;border-radius:50%;
background:var(--ok);flex:none}
.live.warn{color:var(--warn)}
.live.warn .sq{background:var(--warn)}
.usermenu{position:relative}
.userbtn{display:flex;gap:9px;align-items:center;background:var(--color-muted);
border:1px solid var(--color-secondary);border-radius:999px;
padding:4px 12px 4px 4px;color:var(--color-foreground)}
.userbtn:hover{border-color:var(--color-border)}
.userbtn .avatar{width:30px;height:30px;font-size:12px}
.userbtn .meta{text-align:left;line-height:1.15}
.userbtn .meta b{display:block;font-size:13px}
.userbtn .meta span{color:var(--color-muted-foreground);font-size:11.5px}
.dropdown{position:absolute;right:0;top:calc(100% + 8px);width:230px;
background:var(--color-card);border:1px solid var(--color-border);
border-radius:12px;box-shadow:0 16px 32px rgba(15,23,42,.16);
padding:8px;z-index:50}
.dropdown .dhead{padding:8px 10px;border-bottom:1px solid var(--color-secondary);
margin-bottom:6px}
.dropdown .dhead b{display:block;font-size:13.5px}
.dropdown .dhead span{color:var(--color-muted-foreground);font-size:12px}
.dropdown a,.dropdown button.dditem{display:flex;width:100%;gap:9px;
align-items:center;padding:9px 10px;border-radius:8px;font-size:13.5px;
color:var(--color-foreground);text-decoration:none;background:none;
border:none;text-align:left}
.dropdown a:hover,.dropdown button.dditem:hover{background:var(--color-muted)}
main{padding:22px 28px 38px;max-width:1440px;width:100%;margin:0 auto}
.view{display:none}
.view.active{display:block}
h2{font-family:var(--font-heading);font-size:15px;font-weight:600;
margin:26px 0 12px}
.view>h2:first-of-type{margin-top:4px}
.lede{color:var(--color-muted-foreground);max-width:66ch;margin:0 0 14px}
.muted{color:var(--color-muted-foreground)} .small{font-size:12.5px}
/* ---------- quick actions ---------- */
.quick-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;
margin-top:12px}
@media(max-width:1020px){.quick-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:520px){.quick-grid{grid-template-columns:1fr}}
.quick-card{display:flex;gap:12px;align-items:flex-start;
background:var(--color-card);border:1px solid var(--color-secondary);
border-radius:12px;padding:14px 16px;color:var(--color-foreground);
text-decoration:none;transition:border-color 180ms ease}
.quick-card:hover{border-color:var(--color-accent)}
.quick-card svg{flex:none;color:var(--color-accent);margin-top:2px}
.quick-card b{display:block;font-size:14px}
.quick-card span{color:var(--color-muted-foreground);font-size:12.5px}
/* ---------- metric cards ---------- */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:1020px){.cards{grid-template-columns:repeat(2,1fr)}}
@media(max-width:520px){.cards{grid-template-columns:1fr}}
.card{background:var(--color-card);border:1px solid var(--color-secondary);
border-radius:12px;padding:var(--space-xl);box-shadow:var(--shadow-sm)}
.card b{font-family:var(--font-heading);font-size:23px;font-weight:600;
display:block;font-variant-numeric:tabular-nums;letter-spacing:-.01em;
line-height:1.2}
.card span{color:var(--color-muted-foreground);font-size:12.5px}
/* ---------- panels ---------- */
.panel{background:var(--color-card);border:1px solid var(--color-secondary);
border-radius:12px;padding:var(--space-xl) 18px;margin-top:12px;
box-shadow:var(--shadow-sm)}
.panel.flush{padding:0;overflow:hidden}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 20px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
/* ---------- tables ---------- */
table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid var(--color-secondary);
padding:var(--space-md) var(--space-lg);text-align:left;
font-size:13.5px;vertical-align:top}
thead th{color:var(--color-muted-foreground);font-weight:600;
font-size:12.5px}
.panel.flush td:first-child,.panel.flush th:first-child{padding-left:18px}
.panel.flush td:last-child,.panel.flush th:last-child{padding-right:18px}
tbody tr[data-i],tbody tr[data-id]{cursor:pointer;
transition:background 150ms ease}
tbody tr[data-i]:hover,tbody tr[data-id]:hover{background:var(--color-muted)}
tbody tr:last-child td{border-bottom:none}
.tscroll{overflow-x:auto}
.st{font-weight:600;white-space:nowrap}
.st::before{content:"";display:inline-block;width:7px;height:7px;
border-radius:2px;background:currentColor;margin-right:7px;
vertical-align:1px}
.st.ok{color:var(--ok)} .st.info{color:var(--info)}
.st.warn{color:var(--warn)} .st.err{color:var(--color-destructive)}
/* ---------- controls ---------- */
button,.btn{background:var(--color-muted);color:var(--color-foreground);
border:1px solid var(--color-border);border-radius:8px;
padding:8px 13px;font-size:13.5px;text-decoration:none;
display:inline-block;line-height:1.25;
transition:border-color 180ms ease,background 180ms ease,opacity 180ms ease}
button:hover,.btn:hover{border-color:var(--color-muted-foreground)}
button.primary{background:var(--color-accent);
border-color:var(--color-accent);color:var(--color-on-accent);
font-weight:600}
button.primary:hover{opacity:.9}
button.danger:hover{border-color:var(--color-destructive);
color:var(--color-destructive)}
.chip.on{background:var(--color-accent);border-color:var(--color-accent);
color:var(--color-on-accent);font-weight:600}
:focus-visible{outline:2px solid var(--color-accent);outline-offset:2px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;
margin:0 0 12px}
.toolbar input[type=search]{flex:1;min-width:200px}
input[type=text],input[type=password],input[type=search]{
background:var(--color-background);color:var(--color-foreground);
border:1px solid var(--color-border);border-radius:8px;
padding:8px 11px;font-size:14px}
input:focus{border-color:var(--color-accent);outline:none;
box-shadow:0 0 0 3px rgba(79,70,229,.18)}
input[readonly]{width:100%}
.field{margin:13px 0}
.field label{display:block;font-weight:600;font-size:14px;margin-bottom:3px}
.field .help{color:var(--color-muted-foreground);font-size:12.5px}
.field input[type=text],.field input[type=password]{width:min(540px,100%)}
.check{display:flex;gap:9px;align-items:flex-start;font-size:14px}
.check input{margin-top:3px;width:16px;height:16px;flex:none;
accent-color:var(--color-accent)}
.check .help{display:block}
fieldset{border:1px solid var(--color-secondary);border-radius:12px;
padding:6px 18px 14px;margin:0 0 16px;background:var(--color-card)}
legend{font-family:var(--font-heading);font-weight:600;padding:0 6px;
font-size:14px}
.errbar{background:rgba(220,38,38,.06);border:1px solid var(--color-destructive);
color:#B91C1C;border-radius:10px;padding:11px 15px;margin-bottom:16px}
pre{background:var(--color-muted);border:1px solid var(--color-secondary);
border-radius:8px;padding:9px;white-space:pre-wrap;word-break:break-all;
font-size:12px;max-height:260px;overflow:auto;margin:4px 0;
font-family:var(--font-mono)}
.mono{font-family:var(--font-mono);font-size:12.5px;word-break:break-all}
ol.steps{margin:8px 0;padding-left:20px}
ol.steps li{margin:5px 0}
.phase{font-weight:700}
.watchname{color:var(--color-accent);font-weight:700}
.sr{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
/* ---------- detail drawer (right slide-over) ---------- */
.drawer-scrim{position:fixed;inset:0;z-index:55;background:rgba(2,6,16,.55)}
.drawer-scrim[hidden]{display:none}
.drawer{position:fixed;top:0;right:0;bottom:0;z-index:60;
width:min(470px,94vw);background:var(--color-card);
border-left:1px solid var(--color-border);
box-shadow:-18px 0 40px rgba(15,23,42,.18);display:flex;flex-direction:column;
transform:translateX(105%);transition:transform 240ms ease}
.drawer.open{transform:translateX(0)}
.drawer[hidden]{display:none}
.drawer-head{display:flex;gap:10px;align-items:flex-start;
justify-content:space-between;padding:16px 18px;
border-bottom:1px solid var(--color-secondary)}
.drawer-head b{font-family:var(--font-heading);font-size:15.5px}
.drawer-head .sub2{color:var(--color-muted-foreground);font-size:12.5px;
margin-top:2px}
.drawer-body{padding:6px 18px 20px;overflow-y:auto}
.drawer-body table td:first-child{width:150px}
tbody tr.selected{background:var(--color-muted);
box-shadow:inset 3px 0 0 var(--color-accent)}
/* ---------- modal ---------- */
.modal-backdrop{position:fixed;inset:0;z-index:70;background:rgba(2,6,16,.62);
display:flex;align-items:center;justify-content:center;padding:18px}
.modal-backdrop[hidden]{display:none}
.modal{background:var(--color-card);border:1px solid var(--color-border);
border-radius:16px;box-shadow:0 24px 48px rgba(15,23,42,.22);
width:min(520px,100%);max-height:86vh;display:flex;flex-direction:column;
padding:20px 22px;animation:modalIn 180ms ease}
@keyframes modalIn{from{opacity:0;transform:translateY(8px) scale(.98)}
to{opacity:1;transform:none}}
.modal h3{font-family:var(--font-heading);margin:0 0 8px;font-size:16.5px}
.modal .mbody{overflow-y:auto;color:var(--color-foreground)}
.modal .mbody pre{max-height:50vh}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}
button.danger-btn{background:var(--color-destructive);
border-color:var(--color-destructive);color:#fff;font-weight:600}
/* ---------- toasts ---------- */
.toast-stack{position:fixed;top:14px;right:14px;z-index:80;display:flex;
flex-direction:column;gap:8px;width:min(360px,calc(100vw - 28px))}
.toast{display:flex;gap:10px;align-items:flex-start;background:var(--color-card);
border:1px solid var(--color-border);border-left:4px solid var(--ok);
border-radius:10px;padding:11px 12px;font-size:13.5px;
box-shadow:0 12px 28px rgba(15,23,42,.16);animation:toastIn 200ms ease}
.toast.info{border-left-color:var(--info)}
.toast.err{border-left-color:var(--color-destructive)}
.toast span{flex:1}
@keyframes toastIn{from{opacity:0;transform:translateX(14px)}
to{opacity:1;transform:none}}
/* ---------- alert + skeleton ---------- */
.errbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.errbar span{flex:1;min-width:220px}
.skl{height:76px;border-radius:12px;background:var(--color-muted);
border:1px solid var(--color-secondary);animation:pulse 1.3s ease infinite}
@keyframes pulse{0%,100%{opacity:.55}50%{opacity:1}}
/* ---------- desktop: collapsed sidebar ---------- */
.app.sidebar-collapsed .sidebar{width:84px;padding:var(--space-xl) 10px}
.app.sidebar-collapsed .brand{justify-content:center;padding-bottom:var(--space-lg)}
.app.sidebar-collapsed .brand .btext,
.app.sidebar-collapsed .navlabel,
.app.sidebar-collapsed .navlink .label,
.app.sidebar-collapsed .usercard .meta,
.app.sidebar-collapsed .sidever{display:none}
.app.sidebar-collapsed .navlink{justify-content:center;padding:10px}
.app.sidebar-collapsed .navlink .badge{position:absolute;top:2px;right:2px;
margin:0}
.app.sidebar-collapsed .usercard{justify-content:center;padding:8px}
/* ---------- mobile: off-canvas sidebar ---------- */
@media(max-width:920px){
  .sidebar{position:fixed;left:0;top:0;bottom:0;height:100dvh;
  transform:translateX(-105%);transition:transform 220ms ease;
  box-shadow:0 0 44px rgba(0,0,0,.5)}
  .app.nav-open .sidebar{transform:translateX(0)}
  .scrim{display:block;position:fixed;inset:0;z-index:35;
  background:rgba(2,6,16,.6)}
  .scrim[hidden]{display:none}
  .topbar{padding:10px 16px}
  .topbar h1{font-size:16.5px}
  .globalsearch{display:none}
  .userbtn .meta{display:none}
  .userbtn{padding:4px}
  main{padding:16px 16px 28px}
  .card b{font-size:20px}
}
@media (pointer:coarse){
  button,.btn{min-height:44px}
}
@media (prefers-reduced-motion: reduce){*{transition:none!important}}
</style></head><body>
<div class="app" id="appShell">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="logo" aria-hidden="true">PS</div>
      <div class="btext">
        <div class="name">proxy-server<span class="dot">.</span></div>
        <div class="tag">Admin Console</div>
      </div>
    </div>
    <nav aria-label="Menu utama">
      <div class="navgroup">
        <div class="navlabel">Menu utama</div>
        <a class="navlink" href="#/ringkasan" data-view="ringkasan">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
          <span class="label">Dashboard</span></a>
        <a class="navlink" href="#/lalu-lintas" data-view="lalu-lintas">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 7h12M12 3l4 4-4 4M20 17H8M12 13l-4 4 4 4"/></svg>
          <span class="label">Lalu lintas</span></a>
        <a class="navlink" href="#/ditahan" data-view="ditahan">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
          <span class="label">Ditahan</span> <span class="badge" id="interceptBadge" hidden>0</span></a>
      </div>
      <div class="navgroup">
        <div class="navlabel">Konfigurasi</div>
        <a class="navlink" href="#/https" data-view="https">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
          <span class="label">HTTPS / MITM</span></a>
        <a class="navlink" href="#/pengaturan" data-view="pengaturan">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 8h9M19 8h1M4 16h3M13 16h7"/><circle cx="16" cy="8" r="2.2"/><circle cx="10" cy="16" r="2.2"/></svg>
          <span class="label">Pengaturan</span></a>
      </div>
      <div class="navgroup">
        <div class="navlabel">Sistem</div>
        <a class="navlink" href="/__stats">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 19V10M10 19V5M16 19v-8M22 19H2"/></svg>
          <span class="label">Statistik JSON</span></a>
        <a class="navlink" href="/__health">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M3 12h4l2.5-6 4 12L16 12h5"/></svg>
          <span class="label">Status server</span></a>
        <a class="navlink" href="/__ca">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="8" cy="14" r="4.5"/><path d="M11.5 10.5 20 2M17 5l3 3M14 8l2.5 2.5"/></svg>
          <span class="label">Sertifikat CA</span></a>
        <a class="navlink" href="/proxy.pac">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18.5h2"/></svg>
          <span class="label">File PAC (HP)</span></a>
      </div>
    </nav>
    <div class="sidefoot">
      <div class="usercard">
        <div class="avatar" id="sidebarAvatar" aria-hidden="true">OP</div>
        <div class="meta">
          <b id="sidebarUserName">Operator</b>
          <span id="sidebarUserRole">Administrator</span>
        </div>
        <button type="button" class="iconbtn" id="sidebarLogoutBtn"
          title="Keluar" aria-label="Keluar">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M14 4h-6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6M10 12h11M18 8l3 4-3 4"/></svg>
        </button>
      </div>
      <div class="sidever">proxy-server v0.9.5 · Admin Console</div>
    </div>
  </aside>
  <div class="scrim" id="sidebarScrim" hidden></div>

  <div class="content">
    <div class="topbar">
      <div class="left">
        <button type="button" class="iconbtn" id="sidebarToggle"
          title="Buka / lipat menu" aria-label="Buka atau lipat menu">
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
        </button>
        <div>
          <div class="crumb">Admin / <span id="crumbView">Dashboard</span></div>
          <h1 id="viewTitle">Dashboard</h1>
          <div class="sub" id="viewSub">Keadaan proxy saat ini, sekilas.</div>
        </div>
      </div>
      <div class="headctl">
        <div class="globalsearch">
          <label class="sr" for="globalSearch">Cari host di lalu lintas</label>
          <input id="globalSearch" type="search"
            placeholder="Cari host, tekan Enter…">
        </div>
        <span id="livePill" class="live ok"><span class="sq" aria-hidden="true"></span><span id="liveText">Live, menyegarkan tiap 2 detik</span></span>
        <label class="check"><input type="checkbox" id="autoRefresh" checked>
        <span>Segarkan otomatis</span></label>
        <button type="button" id="btnRefresh">Segarkan</button>
        <div class="usermenu">
          <button type="button" class="userbtn" id="userMenuBtn"
            aria-haspopup="true" aria-expanded="false">
            <span class="avatar" id="userAvatar" aria-hidden="true">OP</span>
            <span class="meta"><b id="userNameLabel">Operator</b>
            <span id="userRoleLabel">Administrator</span></span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <div class="dropdown" id="userDropdown" hidden>
            <div class="dhead"><b id="ddUserName">Operator</b>
            <span id="sessionState">Memuat sesi…</span></div>
            <a href="#/pengaturan">Pengaturan</a>
            <a href="/__login">Halaman login</a>
            <button type="button" class="dditem" id="logoutBtn">Keluar</button>
          </div>
        </div>
      </div>
    </div>

    <main>
      <div id="errbar" class="errbar" role="alert" hidden>
        <span>Tidak bisa menghubungi server. Yang tampil adalah data
        terakhir yang berhasil dimuat.</span>
        <button type="button" id="btnRetry">Coba lagi</button>
      </div>

      <section class="view" id="view-ringkasan" aria-label="Ringkasan">
        <div class="cards" id="cards" aria-busy="true">
          <div class="skl"></div><div class="skl"></div>
          <div class="skl"></div><div class="skl"></div>
        </div>

        <div class="quick-grid" aria-label="Aksi cepat">
          <a class="quick-card" href="#/lalu-lintas">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 7h12M12 3l4 4-4 4M20 17H8M12 13l-4 4 4 4"/></svg>
            <span><b>Lihat lalu lintas</b>
            <span>Semua koneksi dan detail payload.</span></span></a>
          <a class="quick-card" href="#/ditahan">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
            <span><b>Periksa yang ditahan</b>
            <span>Teruskan atau tolak intercept.</span></span></a>
          <a class="quick-card" href="#/https">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
            <span><b>Atur HTTPS / MITM</b>
            <span>CA dan host yang diakhiri TLS-nya.</span></span></a>
          <a class="quick-card" href="#/pengaturan">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 8h9M19 8h1M4 16h3M13 16h7"/><circle cx="16" cy="8" r="2.2"/><circle cx="10" cy="16" r="2.2"/></svg>
            <span><b>Buka pengaturan</b>
            <span>Capture, intercept, PAC, dan batas.</span></span></a>
        </div>

        <h2>Lalu lintas terakhir</h2>
        <div class="panel flush">
          <table id="recentMini">
            <thead><tr><th>Waktu</th><th>Method</th><th>Host</th>
            <th>Status</th><th>Ukuran</th></tr></thead>
            <tbody></tbody>
          </table>
        </div>
        <p><a class="btn" href="#/lalu-lintas">Lihat semua lalu lintas</a></p>

        <div class="grid2">
          <div>
            <h2>Host yang dipantau</h2>
            <div class="panel">
              <div id="watch"><p class="muted">Tidak ada watchlist. Jalankan
              dengan <code>--lumi</code> atau <code>--watch HOST</code>.</p></div>
              <table id="watchTable"></table>
              <h3 class="small" style="margin:14px 0 4px">Host tersibuk</h3>
              <table id="tops"></table>
            </div>
          </div>
          <div>
            <h2>Sambungkan HP (PAC)</h2>
            <div class="panel">
              <label for="pacUrl"><b>URL PAC untuk Wi-Fi HP</b></label>
              <p class="help muted small">Di pengaturan Wi-Fi HP pilih proxy
              &ldquo;Auto&rdquo; lalu tempel URL ini. Hanya host di daftar
              PAC yang lewat proxy ini; sisanya langsung.</p>
              <input id="pacUrl" type="text" readonly value="">
              <p><button type="button" id="btnCopyPac">Salin URL PAC</button>
              <span id="pacMsg" class="muted small"></span></p>
              <p class="muted small">Atau proxy &ldquo;Manual&rdquo;: host =
              alamat proxy ini, port = port-nya. Manual mengarahkan semua
              trafik HP lewat sini.</p>
            </div>
          </div>
        </div>
      </section>

      <section class="view" id="view-lalu-lintas" aria-label="Lalu lintas">
        <p class="lede">Payload hanya tampil untuk host milikmu yang ada di
        daftar capture; koneksi lain hanya metadata (host, status, ukuran,
        durasi). Klik baris untuk detailnya.</p>
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
        <div class="panel flush">
          <div class="tscroll"><table id="recent">
            <thead><tr><th>Waktu</th><th>Method</th><th>Host</th><th>Status</th>
            <th>Ukuran</th><th>Durasi</th><th>Keterangan</th></tr></thead>
            <tbody></tbody>
          </table></div>
        </div>
        <p id="recentEmpty" class="muted" hidden>Belum ada lalu lintas yang
        cocok dengan filter ini. Arahkan HP ke proxy ini lalu buka sesuatu,
        atau longgarkan filternya.</p>
      </section>

      <section class="view" id="view-ditahan" aria-label="Ditahan">
        <p class="lede">Request dan response untuk host di daftar intercept
        berhenti di sini dulu. <b>Teruskan</b> = kirim seperti biasa.
        <b>Tolak</b> = putuskan (request ditolak 403, response digagalkan
        502). Lewat batas timeout, yang ditahan diteruskan otomatis.</p>
        <div id="intercepts"><p class="muted">Tidak ada yang sedang ditahan.</p></div>
      </section>

      <section class="view" id="view-https" aria-label="HTTPS MITM">
        <p class="lede">Tanpa MITM, koneksi HTTPS hanya terlihat sebagai
        terowongan CONNECT: host dan ukuran saja, isinya tidak. Dengan
        MITM, proxy mengakhiri TLS untuk host milikmu memakai CA lokal
        sehingga isinya terbaca seperti HTTP biasa.</p>
        <div class="panel" id="mitmPanel"><p class="muted">Memuat status MITM…</p></div>
      </section>

      <section class="view" id="view-pengaturan" aria-label="Pengaturan">
        <div id="settingsForm"><p class="muted">Memuat pengaturan…</p></div>
        <label class="check" style="margin-top:4px">
          <input type="checkbox" id="setPersist" checked>
          <span>Simpan juga ke .env
          <span class="help muted small" style="display:block">Kalau dicentang,
          pilihan di sini tetap berlaku setelah server di-restart.</span></span>
        </label>
        <p><button type="button" class="primary" id="btnSave">Simpan pengaturan</button>
        <span id="settingsMsg" class="muted" role="status"></span></p>
      </section>
    </main>
  </div>
</div>

<div class="drawer-scrim" id="drawerScrim" hidden></div>
<aside class="drawer" id="detail" aria-label="Detail koneksi" hidden>
  <div class="drawer-head">
    <div>
      <b>Detail koneksi</b> <span class="muted" id="detailId"></span>
      <div class="sub2" id="detailSub"></div>
    </div>
    <button type="button" class="iconbtn" id="btnCloseDetail"
      aria-label="Tutup detail koneksi">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>
    </button>
  </div>
  <div class="drawer-body" id="detailBody"></div>
</aside>

<div class="modal-backdrop" id="modalBackdrop" hidden>
  <div class="modal" role="dialog" aria-modal="true"
    aria-labelledby="modalTitle">
    <h3 id="modalTitle"></h3>
    <div class="mbody" id="modalBody"></div>
    <div class="modal-actions">
      <button type="button" id="modalCancel">Batal</button>
      <button type="button" id="modalConfirm" class="primary">Ya</button>
    </div>
  </div>
</div>

<div class="toast-stack" id="toastStack" aria-live="polite"></div>

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
  const cls = st>=500 ? 'err' : st>=400 ? 'warn' : st>=300 ? 'info'
    : st>=200 ? 'ok' : '';
  return `<span class="st ${cls}">${st===0 ? 'belum ada' : st}</span>`; }
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
    `<td class="mono">${esc(e.time)}</td><td>${esc(e.method)}</td>` +
    `<td class="mono ${e.watched?'watchname':''}">${esc(e.host)}</td>` +
    `<td>${statusPill(e.status)}</td><td class="mono">${fmtBytes(e.bytes)}</td>` +
    `<td class="mono">${fmtMs(e.duration_ms)}</td>` +
    `<td>${[e.watched?'<span class="watchname">dipantau</span>':'',
      e.payload?'<span class="muted">payload ada</span>':'']
      .filter(Boolean).join(' · ')}</td></tr>`
  ).join('');
  $('recentEmpty').hidden = list.length > 0;
  $('recent').querySelectorAll('tbody tr[data-i]').forEach(tr=>{
    tr.addEventListener('click', ()=>showDetail(Number(tr.dataset.i)));
    tr.addEventListener('keydown', ev=>{
      if (ev.key==='Enter' || ev.key===' '){
        ev.preventDefault(); showDetail(Number(tr.dataset.i)); }});
  });
  markSelectedRow();
}

function renderIntercepts(pend){
  const badge = $('interceptBadge');
  badge.hidden = !pend.length;
  badge.textContent = pend.length;
  if (!pend.length){
    $('intercepts').innerHTML =
      '<p class="muted">Tidak ada yang sedang ditahan. Intercept hanya ' +
      'menahan host yang ada di daftar host intercept di Pengaturan.</p>';
    return;
  }
  $('intercepts').innerHTML = pend.map(p=>{
    const phase = p.phase === 'request'
      ? 'Request, dari klien ke server (keluar)'
      : 'Response, dari server ke klien (masuk)';
    return `<div class="panel"><span class="phase">#${p.id} · ${esc(phase)}</span><br>` +
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
    if (window._online === false)
      toast('Koneksi ke server pulih. Data sudah live lagi.', 'ok');
    window._online = true;
    $('cards').removeAttribute('aria-busy');
    $('livePill').className = 'live ok';
    $('liveText').textContent = 'Live, menyegarkan tiap 2 detik';
    const c = [['Total request', s.requests], ['Error (5xx)', s.errors],
      ['Data terkirim', fmtBytes(s.bytes_sent)],
      ['Cache hit', s.cache_hits], ['Cache miss', s.cache_misses],
      ['Dibatasi (rate limit)', s.rate_limited], ['Diblokir', s.blocked],
      ['Server menyala sejak', fmtUptime(s.uptime_seconds)]];
    $('cards').innerHTML = c.map(x=>
      `<div class="card"><b>${x[1]}</b><span>${x[0]}</span></div>`).join('');
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
    renderMini();
    const tops = s.top_hosts || [];
    $('tops').innerHTML = '<tr><th>Host</th><th>Request</th></tr>' +
      (tops.length ? tops.map(h=>
        `<tr><td>${esc(h[0])}</td><td>${h[1]}</td></tr>`).join('')
        : '<tr><td class="muted">belum ada data</td><td></td></tr>');
  } catch(e) {
    $('errbar').hidden = false;
    window._online = false;
    $('livePill').className = 'live warn';
    $('liveText').textContent = 'Terputus, mencoba lagi otomatis';
  }
  try {
    const ij = await (await fetch('/__intercepts')).json();
    renderIntercepts(ij.pending || []);
  } catch(e) {}
}
const FIELDS = [
  {group:'Capture payload: lihat isi lalu lintas host milikmu'},
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
  {group:'Intercept: tahan dulu, putuskan kemudian'},
  {k:'INTERCEPT', t:'bool', label:'Aktifkan intercept',
   help:'Request dan response untuk host di daftar bawah ditahan sampai kamu meneruskan atau menolaknya di panel Ditahan.'},
  {k:'INTERCEPT_ALLOW_HOSTS', t:'text', label:'Host yang ditahan',
   help:'Pisahkan dengan koma. Boleh wildcard.'},
  {k:'INTERCEPT_TIMEOUT', t:'text', label:'Batas waktu menahan (detik)',
   help:'Lewat waktu ini, yang ditahan diteruskan otomatis supaya trafikmu tidak menggantung.'},
  {group:'HTTPS (MITM): baca trafik terenkripsi host milikmu'},
  {k:'MITM', t:'bool', label:'Aktifkan MITM',
   help:'Proxy mengakhiri TLS untuk host di daftar bawah memakai CA lokal, sehingga payload HTTPS terbaca seperti HTTP. HP harus mempercayai CA-nya. Lihat panel HTTPS.'},
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
    ? '<span class="st ok">Aktif</span>'
    : '<span class="st warn">Mati</span>'} · CA: ${ca.ready
    ? '<span class="st ok">Siap</span>'
    : (ca.crypto_available
      ? '<span class="st warn">Dibuat saat MITM pertama kali aktif</span>'
      : '<span class="st err">Butuh paket cryptography di server</span>')}</p>`;
  h += `<p class="muted small">Host yang di-MITM: <span class="mono">` +
    `${esc(c.MITM_ALLOW_HOSTS || '(belum ada, isi di Pengaturan)')}</span>` +
    ` · Verifikasi sertifikat asli server tujuan: ` +
    `${ca.verify_upstream ? 'ya' : 'tidak (MITM_VERIFY_UPSTREAM=0)'}</p>`;
  if (ca.fingerprint)
    h += `<p class="muted small">Fingerprint SHA-256 CA, samakan dengan ` +
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
    `yang terbaca, bukan lagi CONNECT buta.</li></ol>`;
  h += `<p class="muted small">Aplikasi yang memakai certificate pinning ` +
    `tetap menolak sertifikat ini; untuk aplikasi milikmu, atur dari sisi ` +
    `aplikasinya. Yang diunduh hanya sertifikat publik CA. Kunci ` +
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
          `placeholder="${isSet ? 'sudah tersimpan, kosongkan untuk mempertahankan' : 'belum diisi'}">` +
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
    h += `<p class="muted small">Pengaturan bind, tersimpan ke .env, ` +
      `berlaku setelah restart: PROXY_HOST=${esc(r.PROXY_HOST)} · ` +
      `PROXY_PORT=${esc(r.PROXY_PORT)} · PROXY_MODE=${esc(r.PROXY_MODE)}` +
      (r.PROXY_UPSTREAM ? ` · PROXY_UPSTREAM=${esc(r.PROXY_UPSTREAM)}` : '') +
      `</p>`;
    const da = c.dashboard_auth || {};
    h += `<p class="muted small">Login dashboard: ` +
      (da.enabled
        ? `aktif untuk pengguna <b>${esc(da.user)}</b>`
        : 'belum aktif. Isi DASHBOARD_AUTH di .env lalu restart ' +
          'untuk mewajibkan login') + `.</p>`;
    $('settingsForm').innerHTML = h;
  } catch(e) {
    $('settingsForm').innerHTML =
      '<p class="muted">Gagal memuat pengaturan. Server tidak menjawab.</p>';
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
    msg.textContent = 'Tersimpan. ' + (r.applied||[]).length +
      ' pengaturan berlaku sekarang' +
      (r.persisted ? ', ditulis ke .env' : ', hanya sesi ini') +
      ((r.restart_required_for||[]).length
        ? '. Perlu restart untuk: ' + r.restart_required_for.join(', ')
        : '') + '.';
    toast('Pengaturan tersimpan dan berlaku sekarang.', 'ok');
  } catch(e) {
    msg.textContent = 'Gagal menyimpan. Server tidak menjawab.';
    toast('Gagal menyimpan pengaturan. Server tidak menjawab.', 'err');
  }
  loadSettings();
};
window.resolveIntercept = async function(id, action){
  if (action === 'drop'){ confirmDrop(id); return; }
  await doResolveIntercept(id, action);
};
async function doResolveIntercept(id, action){
  try {
    await fetch('/__intercept/' + action + '?id=' + id);
    toast(action === 'release'
      ? `Intercept #${id} diteruskan.`
      : `Intercept #${id} ditolak.`, 'ok');
  } catch(e) {
    toast(`Gagal memproses intercept #${id}. Server tidak menjawab.`,
      'err');
  }
  tick();
}
function confirmDrop(id){
  window.openModal({
    title: 'Tolak lalu lintas ini?',
    bodyHtml: '<p>Request yang ditolak diputus dengan 403, response ' +
      'yang ditolak digagalkan dengan 502. Tindakan ini tidak bisa ' +
      'dibatalkan.</p>',
    confirmText: 'Ya, tolak', cancelText: 'Batal', danger: true,
    onConfirm: ()=>doResolveIntercept(id, 'drop')});
}

/* ----- toast + modal ----- */
window.toast = function(msg, type){
  type = type || 'ok';
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  if (type === 'err') t.setAttribute('role', 'alert');
  t.innerHTML = `<span>${esc(msg)}</span>` +
    `<button type="button" class="iconbtn" aria-label="Tutup notifikasi">` +
    `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" ` +
    `stroke="currentColor" stroke-width="2" aria-hidden="true">` +
    `<path d="M6 6l12 12M18 6L6 18"/></svg></button>`;
  t.querySelector('button').addEventListener('click', ()=>t.remove());
  $('toastStack').appendChild(t);
  if (type !== 'err') setTimeout(()=>t.remove(), 4200);
};

window.openModal = function(opts){
  const lastFocus = document.activeElement;
  const backdrop = $('modalBackdrop');
  const confirmBtn = $('modalConfirm'), cancelBtn = $('modalCancel');
  $('modalTitle').textContent = opts.title || '';
  $('modalBody').innerHTML = opts.bodyHtml || '';
  confirmBtn.textContent = opts.confirmText || 'Ya';
  cancelBtn.textContent = opts.cancelText || 'Batal';
  confirmBtn.className = opts.danger ? 'danger-btn' : 'primary';
  backdrop.hidden = false;
  const close = result => {
    backdrop.hidden = true;
    confirmBtn.onclick = cancelBtn.onclick = null;
    backdrop.onclick = null;
    document.removeEventListener('keydown', trap, true);
    if (lastFocus && lastFocus.focus) lastFocus.focus();
    if (result && opts.onConfirm) opts.onConfirm();
  };
  confirmBtn.onclick = ()=>close(true);
  cancelBtn.onclick = ()=>close(false);
  backdrop.onclick = ev=>{ if (ev.target === backdrop) close(false); };
  const trap = ev=>{
    if (ev.key === 'Escape'){ ev.stopPropagation(); close(false); }
    if (ev.key !== 'Tab') return;
    if (ev.shiftKey && document.activeElement === cancelBtn){
      ev.preventDefault(); confirmBtn.focus();
    } else if (!ev.shiftKey && document.activeElement === confirmBtn){
      ev.preventDefault(); cancelBtn.focus();
    }
  };
  document.addEventListener('keydown', trap, true);
  (opts.danger ? cancelBtn : confirmBtn).focus();
};

window.openPayloadModal = function(key){
  const v = (window._fullPayload || {})[key]; if (!v) return;
  window.openModal({
    title: (PAYLOAD_NAMES[key] || key) + ' · ' + fmtBytes(v.size),
    bodyHtml: `<pre>${esc(v.preview)}</pre>` +
      (v.truncated
        ? '<p class="muted small">Tampilan dipotong pada batas ukuran ' +
          'capture yang diatur di Pengaturan.</p>' : ''),
    confirmText: 'Tutup', cancelText: 'Kembali'});
};

window._detailId = null;
window._fullPayload = {};
const PAYLOAD_NAMES = {request:'Payload request',
  response:'Payload response',
  request_decrypted:'Request terdekripsi (AES)',
  response_decrypted:'Response terdekripsi (AES)',
  request_lgeb:'Request terdekripsi (LGEB)',
  response_lgeb:'Response terdekripsi (LGEB)'};

function markSelectedRow(){
  document.querySelectorAll('#recent tbody tr[data-i]').forEach(tr=>{
    const e = (window._shown||[])[Number(tr.dataset.i)];
    tr.classList.toggle('selected', !!e && e.id === window._detailId);
  });
}

function openDrawer(){
  const d = $('detail');
  d.hidden = false;
  $('drawerScrim').hidden = false;
  void d.offsetWidth;
  d.classList.add('open');
  $('btnCloseDetail').focus();
}
window.closeDetail = function(){
  const d = $('detail');
  if (d.hidden) return;
  d.classList.remove('open');
  $('drawerScrim').hidden = true;
  window._detailId = null;
  markSelectedRow();
  setTimeout(()=>{ if (!d.classList.contains('open')) d.hidden = true; },
    250);
};

window.showDetail = function(i){
  const e = (window._shown||[])[i]; if(!e) return;
  window._detailId = e.id;
  window._fullPayload = {};
  const rows = [['Nomor koneksi', '#' + e.id], ['Waktu', e.time],
    ['Klien', e.peer], ['Method', e.method], ['Host', e.host],
    ['Target / path', e.target], ['Status', e.status],
    ['Ukuran (sisi request)', fmtBytes(e.bytes)],
    ['Durasi', fmtMs(e.duration_ms)],
    ['Di watchlist', e.watched ? 'ya' : 'tidak']];
  let h = `<table>` + rows.map(r=>
      `<tr><td class="muted">${r[0]}</td>` +
      `<td>${esc(r[1])}</td></tr>`).join('') + `</table>`;
  if (e.payload){
    for (const k of Object.keys(PAYLOAD_NAMES)){
      const v = e.payload[k];
      if (!v) continue;
      window._fullPayload[k] = v;
      h += `<h3 class="small" style="margin:14px 0 2px">` +
        `${PAYLOAD_NAMES[k]} <span class="muted">(${esc(v.kind)}, ` +
        `${fmtBytes(v.size)}${v.truncated?', terpotong di tampilan':''})` +
        `</span></h3><pre>${esc(v.preview)}</pre>` +
        `<p><button type="button" ` +
        `onclick="openPayloadModal('${k}')">Lihat penuh</button></p>`;
    }
  } else if (String(e.method).toUpperCase() === 'CONNECT'){
    h += `<p class="muted">Payload tidak ada: ini terowongan CONNECT ` +
      `(HTTPS), isinya terenkripsi ujung-ke-ujung antara HP dan server ` +
      `tujuan, proxy hanya meneruskan. Supaya terbaca, aktifkan MITM ` +
      `untuk host ini di Pengaturan dan pasang sertifikat CA di HP.</p>`;
  } else {
    h += `<p class="muted">Payload tidak direkam untuk host ini. ` +
      `Nyalakan "Rekam payload" di Pengaturan dan masukkan host-nya ke ` +
      `daftar host yang direkam.</p>`;
  }
  $('detailBody').innerHTML = h;
  $('detailId').textContent = '#' + e.id;
  $('detailSub').textContent = e.method + ' · ' + e.host;
  openDrawer();
  markSelectedRow();
};

function renderMini(){
  const list = window._recent.slice(0,6);
  const tb = $('recentMini').querySelector('tbody');
  tb.innerHTML = list.length ? list.map(e=>
    `<tr data-id="${e.id}" tabindex="0">` +
    `<td class="mono">${esc(e.time)}</td><td>${esc(e.method)}</td>` +
    `<td class="mono ${e.watched?'watchname':''}">${esc(e.host)}</td>` +
    `<td>${statusPill(e.status)}</td><td class="mono">${fmtBytes(e.bytes)}</td></tr>`
  ).join('') : '<tr><td colspan="5" class="muted">Belum ada lalu lintas. ' +
    'Arahkan HP ke proxy ini lalu buka sesuatu.</td></tr>';
  tb.querySelectorAll('tr[data-id]').forEach(tr=>{
    const go = ()=>gotoDetail(Number(tr.dataset.id));
    tr.addEventListener('click', go);
    tr.addEventListener('keydown', ev=>{
      if (ev.key==='Enter' || ev.key===' '){ ev.preventDefault(); go(); }});
  });
}

function gotoDetail(id){
  window._filter = 'all';
  $('q').value = '';
  document.querySelectorAll('.chip').forEach(x=>
    x.classList.toggle('on', x.dataset.f === 'all'));
  if (location.hash !== '#/lalu-lintas') location.hash = '#/lalu-lintas';
  applyRoute();
  renderRecent();
  const idx = window._shown.findIndex(e=>e.id === id);
  if (idx >= 0) showDetail(idx);
}

const VIEWS = {
  'ringkasan': ['Dashboard', 'Keadaan proxy saat ini, sekilas.'],
  'lalu-lintas': ['Lalu lintas',
    'Semua koneksi yang lewat proxy ini. Klik baris untuk detailnya.'],
  'ditahan': ['Ditahan (intercept)',
    'Lalu lintas yang berhenti dulu menunggu keputusanmu.'],
  'https': ['HTTPS (MITM)',
    'Baca trafik terenkripsi untuk host milikmu.'],
  'pengaturan': ['Pengaturan',
    'Berlaku langsung; simpan ke .env agar tetap ada setelah restart.'],
};
function applyRoute(){
  let v = (location.hash || '').replace('#/', '');
  if (!VIEWS[v]) v = 'ringkasan';
  document.querySelectorAll('.view').forEach(s=>
    s.classList.toggle('active', s.id === 'view-' + v));
  document.querySelectorAll('.navlink').forEach(a=>{
    const on = a.dataset.view === v;
    a.classList.toggle('active', on);
    if (on) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  $('viewTitle').textContent = VIEWS[v][0];
  $('viewSub').textContent = VIEWS[v][1];
  $('crumbView').textContent = VIEWS[v][0];
}
window.addEventListener('hashchange', applyRoute);

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
  $('pacMsg').textContent = 'Tersalin. Tempel di pengaturan Wi-Fi HP.';
  toast('URL PAC tersalin. Tempel di pengaturan Wi-Fi HP.', 'ok');
});
document.addEventListener('keydown', ev=>{
  if (ev.key === 'Escape' && window.closeDetail) window.closeDetail();
});

/* ----- admin shell: sidebar, user menu, session ----- */
const appShell = $('appShell');
function closeMobileNav(){
  appShell.classList.remove('nav-open');
  $('sidebarScrim').hidden = true;
}
$('sidebarToggle').addEventListener('click', ()=>{
  if (window.innerWidth <= 920){
    const open = appShell.classList.toggle('nav-open');
    $('sidebarScrim').hidden = !open;
  } else {
    appShell.classList.toggle('sidebar-collapsed');
  }
});
$('sidebarScrim').addEventListener('click', closeMobileNav);
$('btnCloseDetail').addEventListener('click', ()=>window.closeDetail());
$('drawerScrim').addEventListener('click', ()=>window.closeDetail());
$('btnRetry').addEventListener('click', tick);
document.querySelectorAll('.navlink').forEach(a=>
  a.addEventListener('click', closeMobileNav));
const userDropdown = $('userDropdown');
$('userMenuBtn').addEventListener('click', ev=>{
  ev.stopPropagation();
  const open = userDropdown.hidden;
  userDropdown.hidden = !open;
  $('userMenuBtn').setAttribute('aria-expanded', String(open));
});
document.addEventListener('click', ev=>{
  if (!userDropdown.hidden && !ev.target.closest('.usermenu')){
    userDropdown.hidden = true;
    $('userMenuBtn').setAttribute('aria-expanded', 'false');
  }
});
userDropdown.querySelectorAll('a').forEach(a=>
  a.addEventListener('click', ()=>{ userDropdown.hidden = true; }));
document.addEventListener('keydown', ev=>{
  if (ev.key === 'Escape'){
    userDropdown.hidden = true;
    closeMobileNav();
  }
});
window._session = {auth_enabled:false, authenticated:true, user:'Operator'};
function initials(name){
  const p = String(name || 'Operator').trim().split(' ').filter(Boolean);
  const first = p[0] || 'Operator';
  return (first[0] + (p[1] ? p[1][0] : '')).toUpperCase();
}
async function loadSession(){
  try {
    const s = await (await fetch('/__session')).json();
    window._session = s;
    const name = s.user || 'Operator';
    const role = s.auth_enabled ? 'Administrator' : 'Mode tanpa login';
    $('userNameLabel').textContent = name;
    $('ddUserName').textContent = name;
    $('sidebarUserName').textContent = name;
    $('userRoleLabel').textContent = role;
    $('sidebarUserRole').textContent = role;
    $('userAvatar').textContent = initials(name);
    $('sidebarAvatar').textContent = initials(name);
    $('sessionState').textContent = s.auth_enabled
      ? 'Login aktif, sesi berlaku di browser ini'
      : 'Login belum diaktifkan (DASHBOARD_AUTH kosong)';
    $('logoutBtn').textContent = s.auth_enabled ? 'Keluar'
      : 'Aktifkan login';
  } catch(e) {}
}
async function doLogout(){
  if (!window._session.auth_enabled){ location.href = '/__login'; return; }
  try { await fetch('/__logout', {method:'POST'}); } catch(e) {}
  location.href = '/__login';
}
$('logoutBtn').addEventListener('click', doLogout);
$('sidebarLogoutBtn').addEventListener('click', doLogout);
$('globalSearch').addEventListener('keydown', ev=>{
  if (ev.key !== 'Enter') return;
  ev.preventDefault();
  window._filter = 'all';
  document.querySelectorAll('.chip').forEach(x=>
    x.classList.toggle('on', x.dataset.f === 'all'));
  $('q').value = ev.target.value;
  if (location.hash !== '#/lalu-lintas') location.hash = '#/lalu-lintas';
  applyRoute();
  renderRecent();
});

setInterval(()=>{ if ($('autoRefresh').checked) tick(); }, 2000);
applyRoute();
loadSettings();
loadSession();
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
    p.add_argument("--dashboard-auth", default=os.getenv("DASHBOARD_AUTH", ""),
                   help="dashboard login 'user:password' (separate from "
                        "proxy auth); empty = dashboard login disabled")
    p.add_argument("--dashboard-session-ttl", type=int,
                   default=int(os.getenv("DASHBOARD_SESSION_TTL", "43200")),
                   help="dashboard login session lifetime in seconds")
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
        dashboard_auth=a.dashboard_auth or file_cfg.get("dashboard_auth", ""),
        dashboard_session_ttl=a.dashboard_session_ttl
        or int(file_cfg.get("dashboard_session_ttl", 43200)),
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
