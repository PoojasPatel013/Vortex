from typing import Optional, List
from sqlmodel import Field, SQLModel, create_engine, Session, select
from datetime import datetime
import os

# Database Setup
sqlite_file_name = "vortex.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url)

class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target: str
    status: str # "pending", "completed", "failed"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships could be added here if we separate Vulnerabilities into their own table
    # For simplicity in this MVP, we'll store results as a JSON blob or just link them loosely
    # But a proper relational model is better. Let's do a proper one.

class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    type: str
    severity: str
    description: str
    evidence: Optional[str] = None

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
