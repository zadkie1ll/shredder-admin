import os
from dataclasses import dataclass


def _read_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def _postgres_url_from_env() -> str | None:
    explicit_url = os.getenv("SHREDDER_ADMIN_DATABASE_URL") or os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url

    site_url = os.getenv("SHREDDER_SITE_DATABASE_URL")
    if site_url:
        return site_url

    host = os.getenv("MI_VPN_BOT_POSTGRES_HOST")
    port = os.getenv("MI_VPN_BOT_POSTGRES_PORT")
    user = os.getenv("MI_VPN_BOT_POSTGRES_USER")
    password = os.getenv("MI_VPN_BOT_POSTGRES_PASSWORD")
    db = os.getenv("MI_VPN_BOT_POSTGRES_DB")
    if all([host, port, user, password, db]):
        return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"

    return None


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    database_url: str
    admin_token: str | None
    ui_username: str | None
    ui_password: str | None
    seed_template_path: str | None


def load_settings() -> Settings:
    database_url = _postgres_url_from_env()
    if not database_url:
        raise ValueError(
            "Set SHREDDER_ADMIN_DATABASE_URL, DATABASE_URL, SHREDDER_SITE_DATABASE_URL, "
            "or MI_VPN_BOT_POSTGRES_* envs."
        )

    return Settings(
        host=os.getenv("SHREDDER_ADMIN_HOST", "0.0.0.0"),
        port=_read_int("SHREDDER_ADMIN_PORT", 8015),
        database_url=database_url,
        admin_token=os.getenv("SHREDDER_ADMIN_TOKEN") or None,
        ui_username=os.getenv("SHREDDER_ADMIN_UI_USERNAME") or None,
        ui_password=os.getenv("SHREDDER_ADMIN_UI_PASSWORD") or None,
        seed_template_path=os.getenv("SHREDDER_ADMIN_SEED_TEMPLATE_PATH") or None,
    )


settings = load_settings()
