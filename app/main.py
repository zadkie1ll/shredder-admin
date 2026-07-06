from pathlib import Path

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
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.config import settings
from app.db import AdminConfigRotationState
from app.db import AdminConfigTemplate
from app.db import init_db
from app.db import session_scope


app = FastAPI(title="Shredder Admin", version="0.1.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def require_admin_token(x_admin_token: str | None = Header(default=None)) -> None:
    if settings.admin_token and x_admin_token != settings.admin_token:
        raise HTTPException(status_code=401, detail="Invalid admin token")


def validate_json_template(content: str) -> None:
    try:
        orjson.loads(content)
    except orjson.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc


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
    init_db()
    seed_template_if_needed()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with session_scope() as session:
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
        state = session.get(AdminConfigRotationState, "default")

        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "configs": configs,
                "state": state,
            },
        )


@app.post("/configs")
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
    return RedirectResponse("/", status_code=303)


@app.post("/configs/{config_id}")
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
    return RedirectResponse("/", status_code=303)


@app.post("/configs/{config_id}/clone")
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
    return RedirectResponse("/", status_code=303)


@app.post("/configs/{config_id}/delete")
def delete_config(config_id: int):
    with session_scope() as session:
        config = session.get(AdminConfigTemplate, config_id)
        if config:
            session.delete(config)
    return RedirectResponse("/", status_code=303)


@app.post("/rotation/reset")
def reset_rotation():
    with session_scope() as session:
        state = session.get(AdminConfigRotationState, "default")
        if not state:
            state = AdminConfigRotationState(key="default", last_index=-1)
            session.add(state)
        else:
            state.last_index = -1
    return RedirectResponse("/", status_code=303)


@app.get("/api/config-templates")
def list_config_templates(_: None = Depends(require_admin_token)):
    with session_scope() as session:
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
                "updated_at": config.updated_at.isoformat() if config.updated_at else None,
            }
            for config in configs
        ]


@app.get("/api/config-templates/next")
def get_next_config_template(_: None = Depends(require_admin_token)):
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

        state = session.get(AdminConfigRotationState, "default", with_for_update=True)
        if not state:
            state = AdminConfigRotationState(key="default", last_index=-1)
            session.add(state)
            session.flush()

        next_index = (state.last_index + 1) % len(configs)
        state.last_index = next_index
        config = configs[next_index]

        return {
            "id": config.id,
            "name": config.name,
            "index": next_index,
            "total_active": len(configs),
            "content": config.content,
        }


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)
