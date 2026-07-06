from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import settings


Base = declarative_base()


class AdminConfigTemplate(Base):
    __tablename__ = "admin_config_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    sort_order = Column(Integer, nullable=False, default=100, server_default="100")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AdminConfigRotationState(Base):
    __tablename__ = "admin_config_rotation_state"

    key = Column(String(100), primary_key=True)
    last_index = Column(Integer, nullable=False, default=-1, server_default="-1")
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
