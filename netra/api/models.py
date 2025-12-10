from typing import Optional, Dict, List, Any
from sqlmodel import Field, SQLModel, JSON, Column
from datetime import datetime

class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target: str
    scan_type: str = "full"
    status: str = "pending" 
    created_at: datetime = Field(default_factory=datetime.utcnow)
    options: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    results: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))

class ScanCreate(SQLModel):
    target: str
    scan_type: str = "full"
    options: Dict[str, Any] = {}

class ScanRead(SQLModel):
    id: int
    target: str
    scan_type: str
    status: str
    created_at: datetime
    results: Dict[str, Any]
