import asyncio
import contextlib
import copy
import os
import signal
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import time
import urllib.error
import urllib.request

import orjson


def read_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    return int(value)


ADMIN_URL = os.getenv("WL01_CHECKER_ADMIN_URL", "https://admin.orpheous.ru").rstrip("/")
ADMIN_TOKEN = os.getenv("WL01_CHECKER_ADMIN_TOKEN", "")
SUBSCRIPTION_URL = os.getenv("WL01_CHECKER_SUBSCRIPTION_URL", "")
INTERVAL_SECONDS = read_int("WL01_CHECKER_INTERVAL_SECONDS", 60)
TIMEOUT_SECONDS = read_int("WL01_CHECKER_TIMEOUT_SECONDS", 12)
XRAY_STARTUP_TIMEOUT_SECONDS = read_int("WL01_CHECKER_XRAY_STARTUP_TIMEOUT_SECONDS", 5)
XRAY_PATH = os.getenv("WL01_CHECKER_XRAY_PATH", "xray")
USER_AGENT = os.getenv("WL01_CHECKER_USER_AGENT", "Happ/1.0")
PROBE_HOST = os.getenv("WL01_CHECKER_PROBE_HOST", "www.google.com")
PROBE_PORT = read_int("WL01_CHECKER_PROBE_PORT", 443)
RUN_ONCE = os.getenv("WL01_CHECKER_RUN_ONCE", "false").lower() in {"1", "true", "yes", "on"}
REPORT_RESULTS = os.getenv("WL01_CHECKER_REPORT_RESULTS", "true").lower() not in {
    "0",
    "false",
    "no",
    "off",
}


def log(message: str) -> None:
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def request_json(method: str, url: str, payload: dict | None = None) -> dict | list:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if ADMIN_TOKEN:
        headers["X-Admin-Token"] = ADMIN_TOKEN
    data = None
    if payload is not None:
        data = orjson.dumps(payload)
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return orjson.loads(response.read())


def list_templates() -> list[dict]:
    return request_json("GET", f"{ADMIN_URL}/api/config-templates")


def get_template_source(config_id: int) -> dict:
    return request_json("GET", f"{ADMIN_URL}/api/config-templates/{config_id}/wl01-check-source")


def send_result(
    config_id: int,
    available_count: int,
    total_count: int,
    error: str | None,
    checker_failed: bool = False,
) -> None:
    if not REPORT_RESULTS:
        log(
            f"dry-run result id={config_id} "
            f"available={available_count}/{total_count} checker_failed={checker_failed} "
            f"error={error!r}"
        )
        return
    request_json(
        "POST",
        f"{ADMIN_URL}/api/config-templates/{config_id}/wl01-check-result",
        {
            "available_count": available_count,
            "total_count": total_count,
            "error": error,
            "checker_failed": checker_failed,
        },
    )


def extract_vless_user_id(outbound: dict) -> str | None:
    for vnext in outbound.get("settings", {}).get("vnext", []):
        for user in vnext.get("users", []):
            user_id = user.get("id")
            if isinstance(user_id, str) and user_id:
                return user_id
    return None


def fetch_entry_proxy() -> tuple[dict, str]:
    if not SUBSCRIPTION_URL:
        raise RuntimeError("WL01_CHECKER_SUBSCRIPTION_URL is not set")
    payload = request_json("GET", SUBSCRIPTION_URL)
    if not isinstance(payload, list) or not payload:
        raise RuntimeError("Subscription response must be a non-empty JSON list")
    for outbound in payload[0].get("outbounds", []):
        if outbound.get("tag") == "proxy" and outbound.get("protocol") == "vless":
            user_id = extract_vless_user_id(outbound)
            if not user_id:
                raise RuntimeError("Subscription proxy does not contain a VLESS user id")
            return outbound, user_id
    raise RuntimeError("Subscription does not contain vless outbound with tag=proxy")


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def wait_for_local_port(port: int, timeout: int) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return True
        except OSError:
            await asyncio.sleep(0.1)
    return False


def trim_log(output: bytes, limit: int = 1000) -> str:
    text = output.decode("utf-8", errors="replace").strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def render_template_content(source: dict, default_wl_uuid: str | None = None) -> dict:
    content = source["content"]
    wl_uuid = (
        source.get("wl01_check_uuid")
        or default_wl_uuid
        or "00000000-0000-4000-8000-000000000000"
    )
    rendered = (
        content.replace("{{VLESS_USER}}", wl_uuid)
        .replace("{{ENTRY_NAME}}", "proxy")
        .replace("{{REMARKS}}", "wl01-checker")
    )
    return orjson.loads(rendered)


def find_socks_dialer_tag(config: dict) -> str | None:
    outbounds = config.get("outbounds", [])
    preferred = ["WL-IN", "ROUTING-IN"]
    for tag in preferred:
        if any(outbound.get("tag") == tag and outbound.get("protocol") == "socks" for outbound in outbounds):
            return tag
    for outbound in outbounds:
        if outbound.get("protocol") == "socks":
            return outbound.get("tag")
    return None


def replace_entry_proxy(config: dict, entry_proxy: dict) -> None:
    dialer_tag = find_socks_dialer_tag(config)
    proxy = copy.deepcopy(entry_proxy)
    if dialer_tag:
        proxy.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = dialer_tag

    for index, outbound in enumerate(config.get("outbounds", [])):
        if outbound.get("tag") == "proxy":
            config["outbounds"][index] = proxy
            return
    config.setdefault("outbounds", []).insert(0, proxy)


def force_wl_routing(config: dict) -> None:
    for balancer in config.get("routing", {}).get("balancers", []):
        if balancer.get("tag") == "WL-BALANCER":
            balancer["selector"] = ["__WL01_CHECKER_NEVER_DIRECT__"]
            balancer["fallbackTag"] = "LOOP-WL"


def keep_single_wl01(config: dict, wl_tag: str) -> None:
    outbounds = config.get("outbounds", [])
    kept = []
    for outbound in outbounds:
        tag = outbound.get("tag", "")
        if tag.startswith("WL-01") and tag != wl_tag:
            continue
        kept.append(outbound)
    config["outbounds"] = kept
    for balancer in config.get("routing", {}).get("balancers", []):
        if balancer.get("tag") == "01-FALLBACK":
            balancer["selector"] = [wl_tag]
            balancer["fallbackTag"] = "LOOP-02"


def remap_inbound_ports(config: dict) -> tuple[int, str, dict[str, int]]:
    old_to_new: dict[int, int] = {}
    tag_to_new: dict[str, int] = {}
    probe_port = None
    probe_tag = None

    api = config.get("api")
    if isinstance(api, dict):
        listen = api.get("listen")
        if isinstance(listen, str) and listen:
            api["listen"] = f"127.0.0.1:{free_local_port()}"

    for inbound in config.get("inbounds", []):
        old_port = inbound.get("port")
        new_port = free_local_port()
        inbound["listen"] = "127.0.0.1"
        inbound["port"] = new_port
        if isinstance(old_port, int):
            old_to_new[old_port] = new_port
        tag = inbound.get("tag")
        if isinstance(tag, str):
            tag_to_new[tag] = new_port
        if inbound.get("protocol") in {"mixed", "socks"} and probe_port is None:
            probe_port = new_port
            probe_tag = tag

    for outbound in config.get("outbounds", []):
        if outbound.get("protocol") != "socks":
            continue
        for server in outbound.get("settings", {}).get("servers", []):
            if server.get("address") in {"127.0.0.1", "localhost"}:
                port = server.get("port")
                if port in old_to_new:
                    server["address"] = "127.0.0.1"
                    server["port"] = old_to_new[port]

    if probe_port is None:
        raise RuntimeError("No mixed/socks inbound found for probe")
    if not probe_tag:
        raise RuntimeError("Probe inbound does not have a tag")
    return probe_port, probe_tag, tag_to_new


def force_probe_to_wl_balancer(config: dict, probe_tag: str) -> None:
    config.setdefault("routing", {}).setdefault("rules", []).insert(
        0,
        {
            "type": "field",
            "inboundTag": [probe_tag],
            "balancerTag": "WL-BALANCER",
        },
    )


def socks_tls_probe(proxy_port: int) -> tuple[bool, str | None]:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=TIMEOUT_SECONDS) as sock:
        sock.settimeout(TIMEOUT_SECONDS)
        sock.sendall(b"\x05\x01\x00")
        auth = sock.recv(2)
        if auth != b"\x05\x00":
            return False, f"socks auth failed: {auth!r}"

        host_bytes = PROBE_HOST.encode("ascii")
        if len(host_bytes) > 255:
            return False, "probe host is too long for socks5"
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", PROBE_PORT)
        )
        head = sock.recv(4)
        if len(head) < 4:
            return False, f"socks short response: {head!r}"
        code = head[1]
        atyp = head[3]
        if atyp == 1:
            sock.recv(4)
        elif atyp == 3:
            length = sock.recv(1)[0]
            sock.recv(length)
        elif atyp == 4:
            sock.recv(16)
        else:
            return False, f"socks bad atyp: {atyp}"
        sock.recv(2)
        if code != 0:
            return False, f"socks connect failed code={code}"

        if PROBE_PORT != 443:
            return True, None

        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=PROBE_HOST) as tls_sock:
            tls_sock.settimeout(TIMEOUT_SECONDS)
            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {PROBE_HOST}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            tls_sock.sendall(request.encode("ascii"))
            response = tls_sock.recv(128)
            if response.startswith(b"HTTP/"):
                return True, None
            return False, f"unexpected TLS probe response: {response[:80]!r}"


async def run_xray_probe(config: dict, probe_port: int) -> tuple[bool, str | None]:
    process = None
    config_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fp:
            config_path = fp.name
            fp.write(orjson.dumps(config))

        process = await asyncio.create_subprocess_exec(
            XRAY_PATH,
            "run",
            "-config",
            config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        if not await wait_for_local_port(probe_port, XRAY_STARTUP_TIMEOUT_SECONDS):
            if process.returncode is None:
                process.terminate()
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=2)
            except asyncio.TimeoutError:
                process.kill()
                stdout, stderr = await process.communicate()
            return False, f"xray did not start probe inbound: {trim_log(stderr or stdout)}"

        ok, error = await asyncio.to_thread(socks_tls_probe, probe_port)
        if ok:
            return True, None

        await asyncio.sleep(0.5)
        log_text = ""
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            log_text = trim_log(stderr or stdout)
        if log_text:
            error = f"{error}; {log_text}"
        return False, error
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        if process and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
        if config_path:
            with contextlib.suppress(OSError):
                Path(config_path).unlink()


def wl01_tags(config: dict) -> list[str]:
    return [
        outbound["tag"]
        for outbound in config.get("outbounds", [])
        if isinstance(outbound.get("tag"), str)
        and outbound["tag"].startswith("WL-01")
        and outbound.get("protocol") == "vless"
    ]


async def check_template(template: dict, entry_proxy: dict, subscription_uuid: str) -> None:
    source = get_template_source(template["id"])
    if source.get("is_active"):
        source["wl01_check_uuid"] = subscription_uuid
    base_config = render_template_content(source, default_wl_uuid=subscription_uuid)
    tags = wl01_tags(base_config)
    if not tags:
        send_result(template["id"], 0, 0, "No WL-01 outbounds found", checker_failed=False)
        return

    failures = []
    available = 0
    for tag in tags:
        config = copy.deepcopy(base_config)
        replace_entry_proxy(config, entry_proxy)
        force_wl_routing(config)
        keep_single_wl01(config, tag)
        probe_port, probe_tag, _ = remap_inbound_ports(config)
        force_probe_to_wl_balancer(config, probe_tag)
        ok, error = await run_xray_probe(config, probe_port)
        if ok:
            available += 1
        else:
            failures.append(f"{tag} -> {error}")

    error = "\n".join(failures[:12]) if failures else None
    send_result(template["id"], available, len(tags), error, checker_failed=False)
    log(f"template id={template['id']} {template.get('name')} WL-01 {available}/{len(tags)}")


async def run_once() -> None:
    templates = list_templates()
    entry_proxy, subscription_uuid = fetch_entry_proxy()
    enabled = [
        item
        for item in templates
        if item.get("wl01_check_enabled") and not item.get("is_fallback")
    ]
    for template in enabled:
        try:
            await check_template(template, entry_proxy, subscription_uuid)
        except (urllib.error.URLError, RuntimeError, OSError, TimeoutError) as exc:
            log(f"template id={template.get('id')} checker failed: {type(exc).__name__}: {exc}")
            with contextlib.suppress(Exception):
                send_result(
                    template["id"],
                    0,
                    len(template.get("wl01_servers") or []),
                    f"checker failed: {type(exc).__name__}: {exc}",
                    checker_failed=True,
                )


async def main() -> None:
    if not ADMIN_TOKEN:
        raise RuntimeError("WL01_CHECKER_ADMIN_TOKEN is required")
    if not SUBSCRIPTION_URL:
        raise RuntimeError("WL01_CHECKER_SUBSCRIPTION_URL is required")

    log("WL-01 checker started")
    while True:
        try:
            await run_once()
        except Exception as exc:  # noqa: BLE001
            log(f"loop failed: {type(exc).__name__}: {exc}")
        if RUN_ONCE:
            break
        await asyncio.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
