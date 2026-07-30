import asyncio
import contextlib
import copy
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from secrets import compare_digest
import socket
import tempfile
from urllib.parse import urlsplit
from uuid import UUID

import orjson
import uvicorn
from fastapi import Depends
from fastapi import FastAPI
from fastapi import Form
from fastapi import Header
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic
from fastapi.security import HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete
from sqlalchemy import select
from sqlalchemy import func
from sqlalchemy import or_

from app.config import settings
from app.db import session_scope
from common.models.db import AdminConfigAssignment
from common.models.db import AdminConfigRotationState
from common.models.db import AdminConfigTemplate
from common.models.db import User


app = FastAPI(title="Shredder Admin", version="0.1.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
security = HTTPBasic(auto_error=False)


def validate_uuid(value: str | None) -> str | None:
    value = _strip_optional(value)
    if not value:
        return None
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid WL-01 UUID: {value}") from exc


def require_admin_token(x_admin_token: str | None = Header(default=None)) -> None:
    if settings.admin_token and x_admin_token != settings.admin_token:
        raise HTTPException(status_code=401, detail="Invalid admin token")


def require_ui_auth(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    if not settings.ui_username and not settings.ui_password:
        return

    if not settings.ui_username or not settings.ui_password:
        raise HTTPException(
            status_code=500,
            detail="Both SHREDDER_ADMIN_UI_USERNAME and SHREDDER_ADMIN_UI_PASSWORD must be set.",
        )

    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )

    username_ok = compare_digest(credentials.username, settings.ui_username)
    password_ok = compare_digest(credentials.password, settings.ui_password)
    if not username_ok or not password_ok:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


def validate_json_template(content: str) -> None:
    try:
        orjson.loads(content)
    except orjson.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc


def _json_dump_text(payload) -> str:
    return orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8")


def get_tag_list(content: str, section: str) -> list[str]:
    try:
        payload = orjson.loads(content)
    except orjson.JSONDecodeError:
        return []

    items = payload.get(section, []) if isinstance(payload, dict) else []
    if not isinstance(items, list):
        return []

    tags = []
    for item in items:
        if not isinstance(item, dict):
            continue
        tag = item.get("tag")
        if isinstance(tag, str) and tag:
            tags.append(tag)
    return tags


def get_outbound_tags(content: str) -> list[str]:
    return get_tag_list(content, "outbounds")


def build_yacdn_https_fallback_content(source_content: str) -> str | None:
    try:
        payload = orjson.loads(source_content)
    except orjson.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return None

    cdn_outbound = None
    block_outbound = None
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = outbound.get("tag")
        if tag == "BLOCK":
            block_outbound = copy.deepcopy(outbound)
        if not isinstance(tag, str):
            continue
        if tag.startswith("WL-03") and "YCDN-HTTPS" in tag:
            cdn_outbound = copy.deepcopy(outbound)

    if not cdn_outbound:
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            stream_settings = outbound.get("streamSettings")
            if not isinstance(stream_settings, dict):
                continue
            xhttp_settings = stream_settings.get("xhttpSettings")
            tls_settings = stream_settings.get("tlsSettings")
            if (
                isinstance(xhttp_settings, dict)
                and isinstance(tls_settings, dict)
                and xhttp_settings.get("host") == "cdn1.orpheous.ru"
                and tls_settings.get("serverName") == "cdn1.orpheous.ru"
            ):
                cdn_outbound = copy.deepcopy(outbound)
                break

    if not cdn_outbound or not isinstance(cdn_outbound.get("tag"), str):
        return None

    inbound_tags = [
        item.get("tag")
        for item in payload.get("inbounds", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    ]

    fallback = {
        key: copy.deepcopy(payload[key])
        for key in ("log", "dns", "policy", "api")
        if key in payload
    }
    fallback["remarks"] = "YA CDN HTTPS fallback"
    fallback["inbounds"] = copy.deepcopy(payload.get("inbounds", []))
    fallback["outbounds"] = [cdn_outbound]
    rules = []
    if block_outbound:
        fallback["outbounds"].append(block_outbound)
        rules.append({"network": "udp", "outboundTag": "BLOCK", "port": "443"})
    if inbound_tags:
        rules.append(
            {
                "type": "field",
                "inboundTag": inbound_tags,
                "outboundTag": cdn_outbound["tag"],
            }
        )
    fallback["routing"] = {
        "domainStrategy": payload.get("routing", {}).get("domainStrategy", "IPIfNonMatch")
        if isinstance(payload.get("routing"), dict)
        else "IPIfNonMatch",
        "rules": rules,
    }
    return _json_dump_text(fallback)


def apply_wl01_uuid(content: str, wl01_uuid: str | None) -> str:
    if not wl01_uuid:
        return content

    try:
        payload = orjson.loads(content)
    except orjson.JSONDecodeError:
        return content

    if not isinstance(payload, dict):
        return content

    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return content

    changed = False
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = outbound.get("tag")
        if not isinstance(tag, str) or not tag.startswith("WL-01"):
            continue
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            continue
        vnext = settings.get("vnext")
        if not isinstance(vnext, list):
            continue
        for server in vnext:
            if not isinstance(server, dict):
                continue
            users = server.get("users")
            if not isinstance(users, list):
                continue
            for user in users:
                if isinstance(user, dict):
                    user["id"] = wl01_uuid
                    changed = True

    return _json_dump_text(payload) if changed else content


def content_for_delivery(config: AdminConfigTemplate) -> str:
    return apply_wl01_uuid(config.content, config.wl01_check_uuid)


def extract_wl01_servers(content: str, wl01_uuid: str | None = None) -> list[dict]:
    try:
        payload = orjson.loads(apply_wl01_uuid(content, wl01_uuid))
    except orjson.JSONDecodeError:
        return []

    outbounds = payload.get("outbounds", []) if isinstance(payload, dict) else []
    if not isinstance(outbounds, list):
        return []

    servers: list[dict] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = outbound.get("tag")
        if not isinstance(tag, str) or not tag.startswith("WL-01"):
            continue
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            continue
        vnext = settings.get("vnext")
        if not isinstance(vnext, list):
            continue
        for server in vnext:
            if not isinstance(server, dict):
                continue
            address = server.get("address")
            port = server.get("port")
            if isinstance(address, str) and isinstance(port, int):
                servers.append({"tag": tag, "address": address, "port": port})
    return servers


def extract_wl01_outbounds(content: str, wl01_uuid: str | None = None) -> list[dict]:
    try:
        payload = orjson.loads(apply_wl01_uuid(content, wl01_uuid))
    except orjson.JSONDecodeError:
        return []

    outbounds = payload.get("outbounds", []) if isinstance(payload, dict) else []
    if not isinstance(outbounds, list):
        return []

    return [
        copy.deepcopy(outbound)
        for outbound in outbounds
        if isinstance(outbound, dict)
        and isinstance(outbound.get("tag"), str)
        and outbound["tag"].startswith("WL-01")
        and outbound.get("protocol") == "vless"
    ]


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _trim_log(output: bytes, limit: int = 800) -> str:
    text = output.decode("utf-8", errors="replace").strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


async def _wait_for_local_port(port: int, timeout: int) -> bool:
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


async def _http_proxy_probe(proxy_port: int, timeout: int) -> tuple[bool, str | None]:
    parsed = urlsplit(settings.wl01_probe_url)
    if parsed.scheme != "http" or not parsed.netloc:
        return False, "checker: SHREDDER_ADMIN_WL01_PROBE_URL must be an http:// URL"

    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", proxy_port),
            timeout=timeout,
        )
        request = (
            f"GET {settings.wl01_probe_url} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            "User-Agent: shredder-admin-wl01-checker\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

        decoded = status_line.decode("ascii", errors="replace").strip()
        parts = decoded.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = 0
            if 200 <= status_code < 400:
                return True, None
        return False, f"xray: probe returned {decoded or 'empty response'}"
    except Exception as exc:  # noqa: BLE001 - we store probe diagnostics for UI.
        return False, f"xray: {type(exc).__name__}: {exc}"


async def xray_probe(outbound: dict, timeout: int) -> tuple[bool, str | None]:
    proxy_port = _free_local_port()
    probe_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "wl01-probe-in",
                "listen": "127.0.0.1",
                "port": proxy_port,
                "protocol": "http",
                "settings": {"timeout": timeout},
            }
        ],
        "outbounds": [outbound],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["wl01-probe-in"],
                    "outboundTag": outbound["tag"],
                }
            ]
        },
    }

    process = None
    config_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fp:
            config_path = fp.name
            fp.write(orjson.dumps(probe_config))

        process = await asyncio.create_subprocess_exec(
            settings.wl01_xray_path,
            "run",
            "-config",
            config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if not await _wait_for_local_port(
            proxy_port,
            settings.wl01_xray_startup_timeout_seconds,
        ):
            if process.returncode is None:
                process.terminate()
            stdout, stderr = await process.communicate()
            log = _trim_log(stderr or stdout)
            return False, f"checker: xray did not start probe inbound. {log}".strip()

        ok, error = await _http_proxy_probe(proxy_port, timeout)
        if ok:
            return True, None

        stdout = stderr = b""
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
        log = _trim_log(stderr or stdout)
        if log:
            error = f"{error}; {log}"
        return False, error
    except FileNotFoundError:
        return False, f"checker: xray binary not found at {settings.wl01_xray_path}"
    except Exception as exc:  # noqa: BLE001 - one probe should not stop the checker.
        return False, f"checker: {type(exc).__name__}: {exc}"
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        if config_path:
            with contextlib.suppress(OSError):
                Path(config_path).unlink()


async def check_wl01_template(config_id: int) -> None:
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config or not config.wl01_check_enabled:
            return
        servers = extract_wl01_servers(config.content, config.wl01_check_uuid)
        outbounds = extract_wl01_outbounds(config.content, config.wl01_check_uuid)

    if not servers or not outbounds:
        with session_scope() as session:
            config = session.get(AdminConfigTemplate, config_id)
            if config:
                config.wl01_last_checked_at = func.now()
                config.wl01_last_available_count = 0
                config.wl01_last_total_count = 0
                config.wl01_last_error = "No WL-01 VLESS outbounds found"
                config.updated_at = func.now()
        return

    results = await asyncio.gather(
        *[
            xray_probe(outbound, settings.wl01_check_timeout_seconds)
            for outbound in outbounds
        ]
    )
    available_count = sum(1 for ok, _ in results if ok)
    failed = [
        f'{server["tag"]} {server["address"]}:{server["port"]} -> {error}'
        for server, (ok, error) in zip(servers, results, strict=True)
        if not ok
    ]

    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config:
            return
        config.wl01_last_checked_at = func.now()
        config.wl01_last_available_count = available_count
        config.wl01_last_total_count = len(servers)
        config.wl01_last_error = "\n".join(failed[:12]) if failed else None
        config.updated_at = func.now()

        checker_failed = all(
            error and error.startswith("checker:")
            for ok, error in results
            if not ok
        )
        if (
            settings.wl01_auto_disable_enabled
            and config.is_active
            and not config.is_fallback
            and len(servers) > 0
            and available_count == 0
            and not checker_failed
        ):
            config.is_active = False
            config.wl01_disabled_at = func.now()
            session.execute(
                delete(AdminConfigAssignment).where(
                    AdminConfigAssignment.template_id == config.id
                )
            )


async def wl01_checker_loop() -> None:
    while True:
        try:
            with session_scope() as session:
                config_ids = (
                    session.execute(
                        select(AdminConfigTemplate.id)
                        .where(AdminConfigTemplate.wl01_check_enabled.is_(True))
                    )
                    .scalars()
                    .all()
                )
            for config_id in config_ids:
                await check_wl01_template(config_id)
        except Exception as exc:  # noqa: BLE001 - background task must keep running.
            print(f"WL-01 checker failed: {type(exc).__name__}: {exc}", flush=True)

        await asyncio.sleep(settings.wl01_check_interval_seconds)


def get_active_assignment_counts(session) -> dict[int, int]:
    rows = session.execute(
        select(
            AdminConfigAssignment.template_id,
            func.count(AdminConfigAssignment.user_key),
        )
        .join(User, AdminConfigAssignment.user_id == User.id)
        .where(or_(User.expire_at.is_(None), User.expire_at > func.now()))
        .group_by(AdminConfigAssignment.template_id)
    ).all()
    return {template_id: count for template_id, count in rows}


def get_recent_assignment_counts(session, seconds: int = 30) -> dict[int, int]:
    threshold = datetime.utcnow() - timedelta(seconds=seconds)
    rows = session.execute(
        select(
            AdminConfigAssignment.template_id,
            func.count(AdminConfigAssignment.user_key),
        )
        .join(User, AdminConfigAssignment.user_id == User.id)
        .where(or_(User.expire_at.is_(None), User.expire_at > func.now()))
        .where(AdminConfigAssignment.last_seen_at >= threshold)
        .group_by(AdminConfigAssignment.template_id)
    ).all()
    return {template_id: count for template_id, count in rows}


def list_configs_with_outbounds(session):
    assignment_counts = get_active_assignment_counts(session)
    recent_counts = get_recent_assignment_counts(session)
    configs = (
        session.execute(
            select(AdminConfigTemplate).order_by(
                AdminConfigTemplate.sort_order.asc(),
                AdminConfigTemplate.id.asc(),
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "config": config,
            "outbounds": get_outbound_tags(config.content),
            "wl01_servers": extract_wl01_servers(config.content, config.wl01_check_uuid),
            "assigned_count": assignment_counts.get(config.id, 0),
            "recent_count": recent_counts.get(config.id, 0),
        }
        for config in configs
    ]


def active_configs_count(configs) -> int:
    return sum(
        1
        for item in configs
        if item["config"].is_active and not item["config"].is_fallback
    )


def assigned_users_count(configs) -> int:
    return sum(item["assigned_count"] for item in configs)


def _strip_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_int_optional(value: int | str | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    stripped = value.strip()
    if not stripped:
        return None
    try:
        return int(stripped)
    except ValueError:
        return None


def resolve_assignment_user(
    session,
    user_id: int | None,
    telegram_id: int | None,
    username: str | None,
) -> User | None:
    if user_id is not None:
        user = session.get(User, user_id)
        if user:
            return user

    if telegram_id is not None:
        user = session.scalar(select(User).where(User.telegram_id == telegram_id))
        if user:
            return user

    if username:
        user = session.scalar(select(User).where(User.username == username))
        if user:
            return user

    return None


def build_assignment_key(
    user: User | None,
    user_key: str | None,
    username: str | None,
    telegram_id: int | None,
    remnawave_user_uuid: str | None,
    short_uuid: str | None,
) -> str | None:
    if user:
        return f"user:{user.id}"
    if user_key:
        return user_key
    if username:
        return f"username:{username}"
    if telegram_id is not None:
        return f"telegram:{telegram_id}"
    if remnawave_user_uuid:
        return f"rw:{remnawave_user_uuid}"
    if short_uuid:
        return f"sub:{short_uuid}"
    return None


def pick_next_config(session, configs: list[AdminConfigTemplate]) -> tuple[int, AdminConfigTemplate]:
    state = session.get(AdminConfigRotationState, "default", with_for_update=True)
    if not state:
        state = AdminConfigRotationState(key="default", last_index=-1)
        session.add(state)
        session.flush()

    next_index = (state.last_index + 1) % len(configs)
    state.last_index = next_index
    state.updated_at = func.now()
    return next_index, configs[next_index]


def seed_template_if_needed() -> None:
    if not settings.seed_template_path:
        return

    seed_path = Path(settings.seed_template_path)
    if not seed_path.exists():
        return

    with session_scope() as session:
        existing = session.scalar(select(AdminConfigTemplate.id).limit(1))
        if existing:
            return

        content = seed_path.read_text(encoding="utf-8")
        validate_json_template(content)
        session.add(
            AdminConfigTemplate(
                name="Default template",
                content=content,
                is_active=True,
                sort_order=100,
            )
        )


def ensure_fallback_template() -> None:
    with session_scope() as session:
        fallback = session.scalar(
            select(AdminConfigTemplate)
            .where(AdminConfigTemplate.is_fallback.is_(True))
            .order_by(AdminConfigTemplate.id.asc())
            .limit(1)
        )
        if fallback:
            fallback.is_active = True
            fallback.updated_at = func.now()
            return

        source_templates = (
            session.execute(
                select(AdminConfigTemplate)
                .where(AdminConfigTemplate.is_fallback.is_(False))
                .order_by(AdminConfigTemplate.sort_order.desc(), AdminConfigTemplate.id.desc())
            )
            .scalars()
            .all()
        )
        for source in source_templates:
            content = build_yacdn_https_fallback_content(source.content)
            if not content:
                continue
            session.add(
                AdminConfigTemplate(
                    name="Fallback · YA CDN HTTPS only",
                    content=content,
                    is_active=True,
                    is_fallback=True,
                    wl01_check_enabled=False,
                    sort_order=10000,
                )
            )
            return


@app.on_event("startup")
async def startup() -> None:
    seed_template_if_needed()
    ensure_fallback_template()
    if settings.wl01_checker_enabled:
        app.state.wl01_checker_task = asyncio.create_task(wl01_checker_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "wl01_checker_task", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@app.get("/", dependencies=[Depends(require_ui_auth)])
def index():
    return RedirectResponse("/templates", status_code=303)


@app.get("/templates", response_class=HTMLResponse, dependencies=[Depends(require_ui_auth)])
def templates_list(request: Request):
    with session_scope() as session:
        configs = list_configs_with_outbounds(session)
        state = session.get(AdminConfigRotationState, "default")

        return templates.TemplateResponse(
            "templates.html",
            {
                "request": request,
                "configs": configs,
                "active_count": active_configs_count(configs),
                "assigned_count": assigned_users_count(configs),
                "state": state,
            },
        )


@app.get("/templates/new", response_class=HTMLResponse, dependencies=[Depends(require_ui_auth)])
def new_template(request: Request):
    return templates.TemplateResponse(
        "template_edit.html",
            {
                "request": request,
                "config": None,
                "outbounds": [],
                "wl01_servers": [],
                "assigned_count": 0,
                "recent_count": 0,
                "action": "/configs",
        },
    )


@app.get("/templates/{config_id}", response_class=HTMLResponse, dependencies=[Depends(require_ui_auth)])
def edit_template(request: Request, config_id: int):
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Config not found")

        return templates.TemplateResponse(
            "template_edit.html",
            {
                "request": request,
                "config": config,
                "outbounds": get_outbound_tags(config.content),
                "wl01_servers": extract_wl01_servers(config.content, config.wl01_check_uuid),
                "assigned_count": get_active_assignment_counts(session).get(config.id, 0),
                "recent_count": get_recent_assignment_counts(session).get(config.id, 0),
                "action": f"/configs/{config.id}",
            },
        )


@app.post("/configs", dependencies=[Depends(require_ui_auth)])
def create_config(
    name: str = Form(...),
    sort_order: int = Form(100),
    content: str = Form(...),
    is_active: bool = Form(False),
    wl01_check_enabled: bool = Form(False),
    wl01_check_uuid: str | None = Form(None),
):
    validate_json_template(content)
    normalized_wl01_uuid = validate_uuid(wl01_check_uuid)
    with session_scope() as session:
        session.add(
            AdminConfigTemplate(
                name=name,
                sort_order=sort_order,
                content=content,
                is_active=is_active,
                wl01_check_enabled=wl01_check_enabled,
                wl01_check_uuid=normalized_wl01_uuid,
            )
        )
    return RedirectResponse("/templates", status_code=303)


@app.post("/configs/{config_id}", dependencies=[Depends(require_ui_auth)])
def update_config(
    config_id: int,
    name: str = Form(...),
    sort_order: int = Form(100),
    content: str = Form(...),
    is_active: bool = Form(False),
    wl01_check_enabled: bool = Form(False),
    wl01_check_uuid: str | None = Form(None),
):
    validate_json_template(content)
    normalized_wl01_uuid = validate_uuid(wl01_check_uuid)
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Config not found")
        config.name = name
        config.sort_order = sort_order
        config.content = content
        config.is_active = True if config.is_fallback else is_active
        config.wl01_check_enabled = wl01_check_enabled
        config.wl01_check_uuid = normalized_wl01_uuid
        config.updated_at = func.now()
    return RedirectResponse(f"/templates/{config_id}", status_code=303)


@app.post("/configs/{config_id}/toggle", dependencies=[Depends(require_ui_auth)])
async def toggle_config(config_id: int, request: Request):
    body = await request.json()
    is_active = body.get("is_active")
    if not isinstance(is_active, bool):
        raise HTTPException(status_code=400, detail="is_active must be boolean")
    clear_assignments = bool(body.get("clear_assignments", not is_active))

    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Config not found")
        if config.is_fallback and not is_active:
            raise HTTPException(status_code=400, detail="Fallback config cannot be disabled")
        config.is_active = is_active
        config.updated_at = func.now()
        cleared_assignments = 0
        if not is_active and clear_assignments:
            result = session.execute(
                delete(AdminConfigAssignment).where(
                    AdminConfigAssignment.template_id == config_id
                )
            )
            cleared_assignments = result.rowcount or 0
        return {
            "id": config.id,
            "is_active": config.is_active,
            "cleared_assignments": cleared_assignments,
        }


@app.post("/configs/{config_id}/clone", dependencies=[Depends(require_ui_auth)])
def clone_config(config_id: int):
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Config not found")
        session.add(
            AdminConfigTemplate(
                name=f"{config.name} copy",
                sort_order=config.sort_order + 1,
                content=config.content,
                is_active=False,
                is_fallback=False,
                wl01_check_enabled=config.wl01_check_enabled,
                wl01_check_uuid=config.wl01_check_uuid,
            )
        )
    return RedirectResponse("/templates", status_code=303)


@app.post("/configs/{config_id}/delete", dependencies=[Depends(require_ui_auth)])
def delete_config(config_id: int):
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if config:
            if config.is_fallback:
                raise HTTPException(status_code=400, detail="Fallback config cannot be deleted")
            session.execute(
                delete(AdminConfigAssignment).where(
                    AdminConfigAssignment.template_id == config_id
                )
            )
            session.delete(config)
    return RedirectResponse("/templates", status_code=303)


@app.post("/rotation/reset", dependencies=[Depends(require_ui_auth)])
def reset_rotation():
    with session_scope() as session:
        state = session.get(AdminConfigRotationState, "default")
        if not state:
            state = AdminConfigRotationState(key="default", last_index=-1)
            session.add(state)
        else:
            state.last_index = -1
    return RedirectResponse("/templates", status_code=303)


def serialize_config_templates(session) -> list[dict]:
    assignment_counts = get_active_assignment_counts(session)
    recent_counts = get_recent_assignment_counts(session)
    configs = (
        session.execute(
            select(AdminConfigTemplate).order_by(
                AdminConfigTemplate.sort_order.asc(),
                AdminConfigTemplate.id.asc(),
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": config.id,
            "name": config.name,
            "is_active": config.is_active,
            "is_fallback": config.is_fallback,
            "sort_order": config.sort_order,
            "assigned_count": assignment_counts.get(config.id, 0),
            "recent_count": recent_counts.get(config.id, 0),
            "outbounds": get_outbound_tags(config.content),
            "wl01_check_enabled": config.wl01_check_enabled,
            "wl01_check_uuid": config.wl01_check_uuid,
            "wl01_last_checked_at": (
                config.wl01_last_checked_at.isoformat()
                if config.wl01_last_checked_at
                else None
            ),
            "wl01_last_available_count": config.wl01_last_available_count,
            "wl01_last_total_count": config.wl01_last_total_count,
            "wl01_last_error": config.wl01_last_error,
            "wl01_disabled_at": (
                config.wl01_disabled_at.isoformat() if config.wl01_disabled_at else None
            ),
            "wl01_servers": extract_wl01_servers(config.content, config.wl01_check_uuid),
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        }
        for config in configs
    ]


@app.get("/api/config-templates")
def list_config_templates(_: None = Depends(require_admin_token)):
    with session_scope() as session:
        return serialize_config_templates(session)


@app.get("/api/ui/config-templates", dependencies=[Depends(require_ui_auth)])
def list_config_templates_for_ui():
    with session_scope() as session:
        configs = serialize_config_templates(session)
        state = session.get(AdminConfigRotationState, "default")
        return {
            "configs": configs,
            "active_count": sum(
                1 for config in configs if config["is_active"] and not config["is_fallback"]
            ),
            "fallback_count": sum(1 for config in configs if config["is_fallback"]),
            "assigned_count": sum(config["assigned_count"] for config in configs),
            "last_index": state.last_index if state else -1,
        }


@app.get("/api/config-templates/next")
def get_next_config_template(
    user_key: str | None = None,
    user_id: int | None = None,
    telegram_id: int | None = None,
    username: str | None = None,
    remnawave_user_uuid: str | None = None,
    short_uuid: str | None = None,
    x_user_key: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_telegram_id: str | None = Header(default=None),
    x_username: str | None = Header(default=None),
    x_remnawave_user_uuid: str | None = Header(default=None),
    x_short_uuid: str | None = Header(default=None),
    _: None = Depends(require_admin_token),
):
    normalized_user_key = _strip_optional(user_key) or _strip_optional(x_user_key)
    normalized_user_id = user_id if user_id is not None else _parse_int_optional(x_user_id)
    normalized_telegram_id = (
        telegram_id if telegram_id is not None else _parse_int_optional(x_telegram_id)
    )
    normalized_username = _strip_optional(username) or _strip_optional(x_username)
    normalized_remnawave_user_uuid = (
        _strip_optional(remnawave_user_uuid) or _strip_optional(x_remnawave_user_uuid)
    )
    normalized_short_uuid = _strip_optional(short_uuid) or _strip_optional(x_short_uuid)

    with session_scope() as session:
        configs = (
            session.execute(
                select(AdminConfigTemplate)
                .where(AdminConfigTemplate.is_active.is_(True))
                .where(AdminConfigTemplate.is_fallback.is_(False))
                .order_by(AdminConfigTemplate.sort_order.asc(), AdminConfigTemplate.id.asc())
            )
            .scalars()
            .all()
        )
        using_fallback = False
        if not configs:
            configs = (
                session.execute(
                    select(AdminConfigTemplate)
                    .where(AdminConfigTemplate.is_active.is_(True))
                    .where(AdminConfigTemplate.is_fallback.is_(True))
                    .order_by(
                        AdminConfigTemplate.sort_order.asc(),
                        AdminConfigTemplate.id.asc(),
                    )
                )
                .scalars()
                .all()
            )
            using_fallback = True
        if not configs:
            raise HTTPException(status_code=404, detail="No active config templates")

        assignment_status = "rotated"
        next_index = None
        config = None
        user = resolve_assignment_user(
            session=session,
            user_id=normalized_user_id,
            telegram_id=normalized_telegram_id,
            username=normalized_username,
        )
        assignment_key = build_assignment_key(
            user=user,
            user_key=normalized_user_key,
            username=normalized_username,
            telegram_id=normalized_telegram_id,
            remnawave_user_uuid=normalized_remnawave_user_uuid,
            short_uuid=normalized_short_uuid,
        )

        if assignment_key:
            assignment = session.get(
                AdminConfigAssignment,
                assignment_key,
                with_for_update=True,
            )
            configs_by_id = {item.id: item for item in configs}
            if assignment and assignment.template_id in configs_by_id:
                config = configs_by_id[assignment.template_id]
                next_index = configs.index(config)
                assignment.user_id = user.id if user else assignment.user_id
                assignment.username_snapshot = normalized_username or assignment.username_snapshot
                assignment.telegram_id_snapshot = (
                    normalized_telegram_id or assignment.telegram_id_snapshot
                )
                assignment.remnawave_user_uuid = (
                    normalized_remnawave_user_uuid or assignment.remnawave_user_uuid
                )
                assignment.short_uuid = normalized_short_uuid or assignment.short_uuid
                assignment.request_count += 1
                assignment.last_seen_at = func.now()
                assignment.updated_at = func.now()
                assignment_status = "existing"
            else:
                next_index, config = pick_next_config(session, configs)
                if assignment:
                    assignment.template_id = config.id
                    assignment.user_id = user.id if user else assignment.user_id
                    assignment.username_snapshot = normalized_username or assignment.username_snapshot
                    assignment.telegram_id_snapshot = (
                        normalized_telegram_id or assignment.telegram_id_snapshot
                    )
                    assignment.remnawave_user_uuid = (
                        normalized_remnawave_user_uuid or assignment.remnawave_user_uuid
                    )
                    assignment.short_uuid = normalized_short_uuid or assignment.short_uuid
                    assignment.request_count += 1
                    assignment.last_seen_at = func.now()
                    assignment.updated_at = func.now()
                    assignment_status = "reassigned"
                else:
                    session.add(
                        AdminConfigAssignment(
                            user_key=assignment_key,
                            user_id=user.id if user else None,
                            username_snapshot=normalized_username,
                            telegram_id_snapshot=normalized_telegram_id,
                            remnawave_user_uuid=normalized_remnawave_user_uuid,
                            short_uuid=normalized_short_uuid,
                            template_id=config.id,
                        )
                    )
                    assignment_status = "created"
        else:
            next_index, config = pick_next_config(session, configs)

        assert next_index is not None
        assert config is not None

        return {
            "id": config.id,
            "name": config.name,
            "index": next_index,
            "total_active": len(configs),
            "using_fallback": using_fallback,
            "assignment_status": assignment_status,
            "assignment_key": assignment_key,
            "user_id": user.id if user else None,
            "content": content_for_delivery(config),
        }


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)
