import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy_server.server import Config, Proxy  # noqa: E402


async def origin(reader, writer):
    await reader.readuntil(b"\r\n\r\n")
    body = b"hello-from-origin"
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                 b"Content-Length: " + str(len(body)).encode() +
                 b"\r\nConnection: close\r\n\r\n" + body)
    await writer.drain()
    writer.close()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def scenario():
    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]

    proxy = Proxy(Config())
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    # health endpoint
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(b"GET /__health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = await r.read()
    assert b"200 OK" in data and b'"ok"' in data
    w.close()

    # forward proxy to local origin
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n".encode())
    data = await r.read()
    assert b"hello-from-origin" in data, data
    w.close()

    proxy_server.close()
    origin_server.close()


def test_proxy_end_to_end():
    run(scenario())


async def scenario_features():
    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]

    cfg = Config(cache_ttl=60, rate_limit=0, block_hosts=("blocked.example",))
    proxy = Proxy(cfg)
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    async def get(url):
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        host = url.split("/")[2]
        w.write(f"GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = await r.read()
        w.close()
        return data

    url = f"http://127.0.0.1:{origin_port}/"
    assert b"hello-from-origin" in await get(url)
    assert b"hello-from-origin" in await get(url)          # 2nd = cache hit
    assert proxy.stats.cache_hits == 1, proxy.stats.snapshot()

    blocked = await get("http://blocked.example/")
    assert b"403" in blocked, blocked

    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(b"GET /__stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = await r.read()
    assert b'"requests"' in data and b'"cache_hits": 1' in data, data
    w.close()

    # rate limit: 2 forward req/min, the 3rd is 429 (health/stats are exempt)
    proxy2 = Proxy(Config(rate_limit=2))
    srv2 = await asyncio.start_server(proxy2.handle, "127.0.0.1", 0)
    port2 = srv2.sockets[0].getsockname()[1]
    codes = []
    for _ in range(3):
        r, w = await asyncio.open_connection("127.0.0.1", port2)
        w.write(f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n".encode())
        codes.append((await r.read()).split(b" ")[1])
        w.close()
    assert codes[2] == b"429", codes
    srv2.close()
    proxy_server.close()
    origin_server.close()


def test_features():
    run(scenario_features())


async def scenario_dashboard():
    from proxy_server.server import LUMI_WATCH_HOSTS, host_matches
    assert host_matches("lumigo-cn-prod-vs.bilibiligame.net", LUMI_WATCH_HOSTS)
    assert host_matches("api.bilibili.com", LUMI_WATCH_HOSTS)
    assert not host_matches("example.com", LUMI_WATCH_HOSTS)

    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]
    proxy = Proxy(Config(watch_hosts=LUMI_WATCH_HOSTS))
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    async def raw(req):
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        w.write(req)
        data = await r.read()
        w.close()
        return data

    # one normal request -> appears in recent
    data = await raw(f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
                     f"Host: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n".encode())
    assert b"hello-from-origin" in data

    # dashboard page
    data = await raw(b"GET /__dashboard HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b"proxy-server dashboard" in data and b"Lumi" in data, data[:200]

    # stats: recent + watch structure
    data = await raw(b"GET /__stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b'"recent"' in data and b'"watch"' in data and b"bilibiligame" in data, data

    # simulate a watched host in stats directly (no live DNS needed)
    proxy.stats.record("lumigo-cn-prod-vs.bilibiligame.net", 200, 123)
    proxy.stats.record_event("12:00:00", "GET",
                             "lumigo-cn-prod-vs.bilibiligame.net", 200, 123, 5)
    snap = proxy.stats.snapshot()
    assert snap["watch"]["total_requests"] == 1, snap["watch"]
    assert snap["watch"]["recent"][0]["watched"] is True

    proxy_server.close()
    origin_server.close()


def test_dashboard_and_lumi_watch():
    run(scenario_dashboard())


async def scenario_detail():
    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]
    proxy = Proxy(Config())
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(f"GET http://127.0.0.1:{origin_port}/some/path?q=1 HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n".encode())
    assert b"hello-from-origin" in await r.read()
    w.close()
    ev = proxy.stats.recent[0]
    assert "/some/path?q=1" in ev["target"], ev
    assert "127.0.0.1" in ev["peer"], ev
    assert "id" in ev and ev["payload"] is None, ev
    # dashboard carries the detail panel + click handler
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(b"GET /__dashboard HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = await r.read()
    assert b"showDetail" in data and b"Connection detail" in data
    w.close()
    proxy_server.close()
    origin_server.close()


def test_connection_detail_metadata():
    run(scenario_detail())


async def echo_origin(reader, writer):
    raw = await reader.readuntil(b"\r\n\r\n")
    length = 0
    for line in raw.decode("iso-8859-1").split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1])
    body = await reader.readexactly(length) if length else b""
    reply = b"echo:" + body
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                 b"Content-Length: " + str(len(reply)).encode() +
                 b"\r\nConnection: close\r\n\r\n" + reply)
    await writer.drain()
    writer.close()


async def scenario_payload():
    from proxy_server.server import payload_forbidden
    assert payload_forbidden("api.bilibili.com")
    assert payload_forbidden("lumigo-cn-prod-vs.bilibiligame.net")
    assert not payload_forbidden("127.0.0.1")

    origin_server = await asyncio.start_server(echo_origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]

    # capture ON for own host (127.0.0.1)
    proxy = Proxy(Config(payload_capture=True,
                         payload_allow_hosts=("127.0.0.1",)))
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(f"POST http://127.0.0.1:{origin_port}/submit HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\nContent-Length: 5\r\n"
            f"Connection: close\r\n\r\nhello".encode())
    data = await r.read()
    assert b"echo:hello" in data, data
    w.close()
    ev = proxy.stats.recent[0]
    assert ev["payload"]["request"]["preview"] == "hello", ev
    assert ev["payload"]["response"]["preview"] == "echo:hello", ev
    proxy_server.close()

    # capture OFF by default -> no payload stored
    proxy2 = Proxy(Config())
    srv2 = await asyncio.start_server(proxy2.handle, "127.0.0.1", 0)
    port2 = srv2.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port2)
    w.write(f"POST http://127.0.0.1:{origin_port}/submit HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\nContent-Length: 5\r\n"
            f"Connection: close\r\n\r\nhello".encode())
    await r.read()
    w.close()
    assert proxy2.stats.recent[0]["payload"] is None
    srv2.close()
    origin_server.close()


def test_payload_capture_own_host():
    run(scenario_payload())


async def scenario_intercept():
    from proxy_server.server import payload_forbidden
    assert payload_forbidden("api.bilibili.com")  # intercept guard source

    origin_server = await asyncio.start_server(echo_origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]
    proxy = Proxy(Config(intercept=True,
                         intercept_allow_hosts=("127.0.0.1",),
                         intercept_timeout=10))
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    async def call_api(path):
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        w.write(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        data = await r.read()
        w.close()
        return data

    async def wait_phase(phase):
        for _ in range(100):
            await asyncio.sleep(0.05)
            for item in proxy.intercepts.values():
                if item["phase"] == phase:
                    return item["id"]
        raise AssertionError(f"no {phase} intercept appeared")

    async def do_post():
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        w.write(f"POST http://127.0.0.1:{origin_port}/x HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\nContent-Length: 2\r\n"
                f"Connection: close\r\n\r\nhe".encode())
        data = await r.read()
        w.close()
        return data

    # release request, then release response -> client gets the echo
    task = asyncio.create_task(do_post())
    rid = await wait_phase("request")
    assert proxy.intercepts[rid]["body"]["preview"] == "he"
    assert b'"pending"' in await call_api("/__intercepts")
    await call_api(f"/__intercept/release?id={rid}")
    sid = await wait_phase("response")
    assert proxy.intercepts[sid]["body"]["preview"] == "echo:he"
    await call_api(f"/__intercept/release?id={sid}")
    assert b"echo:he" in await task

    # drop the request -> client gets 403, origin never answers
    task = asyncio.create_task(do_post())
    rid = await wait_phase("request")
    await call_api(f"/__intercept/drop?id={rid}")
    assert b"403" in await task

    proxy_server.close()
    origin_server.close()


def test_intercept_bidirectional():
    run(scenario_intercept())


async def scenario_config_dashboard():
    import json as _json
    import os
    import tempfile

    secret = "aabbccddeeff00112233445566778899"
    proxy = Proxy(Config(payload_lgeb_salt_hex=secret))
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    async def req(method, path, body=b""):
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        head = (f"{method} {path} HTTP/1.1\r\nHost: x\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
        w.write(head.encode() + body)
        data = await r.read()
        w.close()
        return _json.loads(data.partition(b"\r\n\r\n")[2])

    # view: values visible, secret value never leaks, only "is set"
    snap = await req("GET", "/__config")
    assert snap["secrets_set"]["PAYLOAD_LGEB_SALT_HEX"] is True, snap
    assert secret.encode() not in _json.dumps(snap).encode(), snap
    assert snap["PAYLOAD_CAPTURE"] is False

    # live apply without persist
    out = await req("POST", "/__config",
                    b"PAYLOAD_CAPTURE=1&PAYLOAD_ALLOW_HOSTS=127.0.0.1"
                    b"&INTERCEPT=1&INTERCEPT_TIMEOUT=9&PERSIST=0")
    assert out["ok"] and out["persisted"] is False, out
    assert proxy.cfg.payload_capture is True
    assert proxy.cfg.intercept is True
    assert proxy.cfg.intercept_timeout == 9.0
    snap = await req("GET", "/__config")
    assert snap["PAYLOAD_ALLOW_HOSTS"] == "127.0.0.1", snap

    # secret rotation: set-only, new value applies but still never shown
    new_secret = "99887766554433221100ffeeddccbbaa"
    out = await req("POST", "/__config",
                    f"PAYLOAD_LGEB_SALT_HEX={new_secret}&PERSIST=0".encode())
    assert "PAYLOAD_LGEB_SALT_HEX" in out["applied"], out
    assert proxy.cfg.payload_lgeb_salt_hex == new_secret
    snap = await req("GET", "/__config")
    assert new_secret.encode() not in _json.dumps(snap).encode()

    # persist: merges into the env file named by PROXY_ENV_FILE
    with tempfile.TemporaryDirectory() as td:
        env_path = os.path.join(td, ".env")
        with open(env_path, "w") as fh:
            fh.write("EXISTING=keepme\nPAYLOAD_CAPTURE=0\n")
        old = os.environ.get("PROXY_ENV_FILE")
        os.environ["PROXY_ENV_FILE"] = env_path
        try:
            out = await req("POST", "/__config",
                            b"PAYLOAD_CAPTURE=1&PROXY_RATE_LIMIT=42&PERSIST=1")
        finally:
            if old is None:
                os.environ.pop("PROXY_ENV_FILE", None)
            else:
                os.environ["PROXY_ENV_FILE"] = old
        assert out["persisted"] is True, out
        text = open(env_path).read()
        assert "EXISTING=keepme" in text and "PAYLOAD_CAPTURE=1" in text
        assert "PROXY_RATE_LIMIT=42" in text, text
        assert proxy.cfg.rate_limit == 42 and proxy.limiter.limit == 42

    # dashboard carries the interactive settings panel
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(b"GET /__dashboard HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = await r.read()
    w.close()
    assert b"saveSettings" in data and b"Settings" in data, data[:200]
    proxy_server.close()


def test_config_dashboard():
    run(scenario_config_dashboard())


async def scenario_pac():
    proxy = Proxy(Config(port=8080, pac_hosts=("a.example.com", "*.b.example"),
                         public_host="vps.example:8080"))
    proxy_server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(b"GET /proxy.pac HTTP/1.1\r\nHost: vps.example:8080\r\nConnection: close\r\n\r\n")
    data = await r.read()
    w.close()
    assert b"application/x-ns-proxy-autoconfig" in data, data[:200]
    assert b"FindProxyForURL" in data and b"PROXY vps.example:8080" in data
    assert b'a.example.com' in data and b"dnsDomainIs" in data
    assert b'"DIRECT"' in data, data
    # no PAC_HOSTS -> falls back to routing everything via B
    proxy2 = Proxy(Config(port=9999))
    text = proxy2.pac_text("myhost:9999")
    assert 'return "PROXY myhost:9999"' in text, text
    proxy_server.close()


def test_pac_file():
    run(scenario_pac())


def test_lgeb_reader_own_server():
    import hashlib

    from proxy_server.server import (
        extract_content_hash, payload_forbidden, try_lgeb_decrypt)

    # contentHash naming rule (generic format rule, no server data)
    h = "0123456789abcdef0123456789abcdef"
    assert extract_content_hash(f"/bundles/x_{h}.bundle") == h
    assert extract_content_hash("/bundles/plain.bundle") == ""
    # guard still applies to the LGEB path
    assert payload_forbidden("lumigo-cn-prod-vs.bilibiligame.net")

    salt_hex = "00112233445566778899aabbccddeeff"  # test salt for server A
    res_version = 7
    plain = b"UnityFS-synthetic-test-bundle"

    # no salt in env -> explicit note, no decryption attempted
    blob = b"LGEB" + res_version.to_bytes(4, "little") + b"\x00" * 32
    note = try_lgeb_decrypt(blob, "", h)
    assert note and note["kind"] == "note" and "SALT" in note["preview"], note
    # non-LGEB bodies are ignored
    assert try_lgeb_decrypt(b"plain body", salt_hex, h) is None

    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
    except ImportError:
        return  # decrypt path is exercised in the venv run; note path above ok

    digest = hashlib.sha256(
        bytes.fromhex(salt_hex) + f"{h}:{res_version}".encode()).digest()
    pad = 16 - len(plain) % 16
    padded = plain + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(digest[:16]), modes.CBC(digest[16:])).encryptor()
    blob = b"LGEB" + res_version.to_bytes(4, "little") + (
        enc.update(padded) + enc.finalize())
    out = try_lgeb_decrypt(blob, salt_hex, h)
    assert out and out["preview"] == plain.decode(), out
    assert out["lgeb"] == {"res_version": res_version, "content_hash": h}, out
    # wrong salt -> must not yield the plaintext
    bad = try_lgeb_decrypt(blob, "ff" * 16, h)
    assert not bad or bad.get("preview") != plain.decode()
