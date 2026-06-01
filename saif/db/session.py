from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from saif.config import get_settings


def get_engine():
    return create_engine(get_settings().database_url, pool_pre_ping=True)


SessionLocal = sessionmaker(autocommit=False, autoflush=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    engine = get_engine()
    SessionLocal.configure(bind=engine)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
