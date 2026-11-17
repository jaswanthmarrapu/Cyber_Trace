import os
import logging
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("cybertrace.database")

# Path and database configuration driven by unified Settings
DATABASE_URL = settings.DATABASE_URL
DB_PATH = str(settings.SQLITE_DB_PATH)

# Ensure database directory exists before engine initialization
db_dir = os.path.dirname(DB_PATH)
if db_dir:
    try:
        os.makedirs(db_dir, exist_ok=True)
    except OSError as err:
        logger.warning(f"Could not pre-create database directory '{db_dir}': {err}")

# Create SQLAlchemy engine with multi-threaded connection handling and busy timeout
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 30  # Wait up to 30s during concurrent worker writes
    } if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency for obtaining a database session per request with transaction rollback on error."""
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        db.rollback()
        logger.error(f"Database session rolled back due to error: {exc}")
        raise
    finally:
        db.close()

def init_db():
    """Initialize all database tables automatically without dropping or wiping existing records."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        try:
            os.makedirs(db_dir, exist_ok=True)
        except OSError as err:
            logger.warning(f"Notice on database directory creation: {err}")

    import app.models  # Ensure models are registered with Base metadata
    Base.metadata.create_all(bind=engine)
    logger.info(f"Verified and initialized SQLite database schema at: '{DB_PATH}'")

    # Initialize raw SQLite tables for forensic modules if using SQLite
    if DATABASE_URL.startswith("sqlite"):
        try:
            from app.forensic.case_engine import init_case_management_tables
            from app.forensic.threat_engine import init_threat_detection_tables
            from app.forensic.timeline_engine import init_timeline_tables

            init_case_management_tables(DB_PATH)
            init_threat_detection_tables(DB_PATH)
            init_timeline_tables(DB_PATH)
            logger.info("Forensic engine SQLite tables verified successfully.")
        except Exception as ex:
            logger.warning(f"Forensic table pre-initialization notice: {ex}")

def check_db_health() -> bool:
    """Probe verifying that the persistent database is connected, readable, and operational."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as ex:
        logger.error(f"Database health check failed: {ex}")
        return False
