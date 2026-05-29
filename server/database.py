"""SQLAlchemy database setup and session management."""

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, Session

from server.models import Base
from server.config import get_settings

settings = get_settings()

# Create engine
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False}
    if "sqlite" in settings.DATABASE_URL
    else {},
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """FastAPI dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and apply small compatibility migrations."""
    Base.metadata.create_all(bind=engine)
    _ensure_agent_company_column()


def _ensure_agent_company_column() -> None:
    """Add the company column on databases created before agent tagging."""
    inspector = inspect(engine)
    if "agents" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("agents")}
    if "company" in columns:
        return

    with engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE agents ADD COLUMN company VARCHAR(255) DEFAULT ''")
        )
