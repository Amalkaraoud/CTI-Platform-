import structlog
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from typing import Generator
import os

logger = structlog.get_logger(__name__)

def _default_postgres_url() -> str:
    """Build the URL from POSTGRES_* variables; no credential is embedded in the code."""
    from urllib.parse import quote
    user = os.getenv("POSTGRES_USER", "onyx_admin")
    pw = quote(os.getenv("POSTGRES_PASSWORD", ""), safe="")
    host = os.getenv("POSTGRES_HOST", "localhost")
    return f"postgresql://{user}:{pw}@{host}:5432/onyx_cti"


POSTGRES_URL = os.getenv("POSTGRES_URL") or _default_postgres_url()

Base = declarative_base()

class PostgresService:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None

    def connect(self):
        try:
            self.engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            logger.info("PostgreSQL engine created successfully")
        except Exception as e:
            logger.error("Failed to connect to PostgreSQL", error=str(e))

    def get_db(self) -> Generator:
        if not self.SessionLocal:
            self.connect()
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()

postgres_service = PostgresService()
