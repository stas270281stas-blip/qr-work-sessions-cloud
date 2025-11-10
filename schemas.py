from pydantic import BaseModel, EmailStr
from typing import Optional, Literal, List
from datetime import datetime

class LoginIn(BaseModel):
    email: EmailStr; password: str

class TokenOut(BaseModel):
    access_token: str

class ScanIn(BaseModel):
    qr_payload: str
    lat: Optional[float] = None
    lon: Optional[float] = None
    device_ts: Optional[datetime] = None

class SessionOut(BaseModel):
    id: str; user_id: str; vehicle_id: str
    started_at: Optional[datetime]; ended_at: Optional[datetime]
    status: Literal["open","closed"]
    started_city: Optional[str]; ended_city: Optional[str]
    work_minutes: Optional[int] = None

class ListSessionsOut(BaseModel):
    items: List[SessionOut]

class AdminUserCreate(BaseModel):
    email: EmailStr; password: str
    full_name: Optional[str] = None
    role: Literal['user','admin'] = 'user'

class AdminUserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[Literal['user','admin']] = None
    password: Optional[str] = None

class UserOut(BaseModel):
    id: str; email: EmailStr; full_name: Optional[str] = None; role: Literal['user','admin']
