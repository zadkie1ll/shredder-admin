from datetime import datetime
from datetime import timedelta
from pathlib import Path
from secrets import compare_digest

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
            "assigned_count": assignment_counts.get(config.id, 0),
            "recent_count": recent_counts.get(config.id, 0),
        }
        for config in configs
    ]


def active_configs_count(configs) -> int:
    return sum(1 for item in configs if item["config"].is_active)


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


@app.on_event("startup")
def startup() -> None:
    seed_template_if_needed()


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
):
    validate_json_template(content)
    with session_scope() as session:
        session.add(
            AdminConfigTemplate(
                name=name,
                sort_order=sort_order,
                content=content,
                is_active=is_active,
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
):
    validate_json_template(content)
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Config not found")
        config.name = name
        config.sort_order = sort_order
        config.content = content
        config.is_active = is_active
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
            )
        )
    return RedirectResponse("/templates", status_code=303)


@app.post("/configs/{config_id}/delete", dependencies=[Depends(require_ui_auth)])
def delete_config(config_id: int):
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if config:
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
            "sort_order": config.sort_order,
            "assigned_count": assignment_counts.get(config.id, 0),
            "recent_count": recent_counts.get(config.id, 0),
            "outbounds": get_outbound_tags(config.content),
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
            "active_count": sum(1 for config in configs if config["is_active"]),
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
                .order_by(AdminConfigTemplate.sort_order.asc(), AdminConfigTemplate.id.asc())
            )
            .scalars()
            .all()
        )
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
            "assignment_status": assignment_status,
            "assignment_key": assignment_key,
            "user_id": user.id if user else None,
            "content": config.content,
        }


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)
