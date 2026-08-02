import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database URL - SQLite for MVP, can be replaced by PostgreSQL easily via env vars
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/sentinel.db")

# Ensure the database directory exists if using SQLite
if DATABASE_URL.startswith("sqlite:///"):
    db_dir = os.path.dirname(DATABASE_URL.replace("sqlite:///", ""))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

# Create SQLAlchemy engine
# connect_args={"check_same_thread": False} is required only for SQLite
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite:///") else {}
)

# Session local factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base for models
Base = declarative_base()

def get_db():
    """Dependency injection helper to yield a DB session and ensure cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
