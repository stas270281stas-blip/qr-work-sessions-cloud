from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import os, json, hashlib, requests

from models import Base, User, Vehicle, WorkSession
from auth import make_hash, verify_pwd, mint_token, require_auth, require_admin, AuthUser
from schemas import *

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

app = FastAPI(title="QR Work Sessions")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_headers=["*"], allow_methods=["*"])

def now(): return datetime.utcnow()
MAX_BACKFILL_HOURS = 48; FUTURE_GRACE_SEC = 120; MIN_DURATION_MIN = 1

def clamp_ts(device_ts, fallback, lower_bound=None):
    if not device_ts: return fallback, False
    lb = fallback - timedelta(hours=MAX_BACKFILL_HOURS); ub = fallback + timedelta(seconds=FUTURE_GRACE_SEC)
    ts = device_ts
    if ts < lb: ts = lb
    if ts > ub: ts = ub
    if lower_bound and ts <= lower_bound: ts = lower_bound + timedelta(minutes=MIN_DURATION_MIN)
    return ts, True

def minutes(s): 
    if s.started_at and s.ended_at: return max(0, int((s.ended_at - s.started_at).total_seconds() // 60))
    return None

def reverse_city(lat, lon):
    if lat is None or lon is None: return "unknown"
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
            params={"format":"jsonv2","lat":lat,"lon":lon,"zoom":10,"addressdetails":1},
            headers={"User-Agent":"qr-work-sessions/1.0"}, timeout=5)
        if r.ok:
            a = r.json().get("address",{})
            return a.get("city") or a.get("town") or a.get("village") or a.get("state") or "unknown"
        return "unknown"
    except Exception: return "unknown"

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn):
    db = SessionLocal(); u = db.query(User).filter(User.email==str(data.email)).first()
    if not u or not verify_pwd(data.password, u.password_hash): raise HTTPException(401, "Bad credentials")
    return {"access_token": mint_token(u.id, u.email, u.role)}

def vehicle_from_qr(db, payload: str):
    number = payload.split(":",1)[-1].strip() if ":" in payload else payload.strip()
    v = db.query(Vehicle).filter(Vehicle.number==number).first()
    if not v: v = Vehicle(number=number); db.add(v); db.commit()
    return v

@app.post("/sessions/scan", response_model=SessionOut)
def scan(data: ScanIn, user: AuthUser = Depends(require_auth), Idempotency_Key: str | None = Header(default=None)):
    db = SessionLocal()
    open_mine = db.query(WorkSession).filter(WorkSession.user_id==user.id, WorkSession.status=="open").first()
    if open_mine:
        ended_ts, used = clamp_ts(data.device_ts, now(), lower_bound=open_mine.started_at)
        open_mine.ended_at = ended_ts
        open_mine.ended_city = reverse_city(data.lat, data.lon) if not open_mine.ended_city else open_mine.ended_city
        open_mine.ended_from_device = used
        open_mine.status = "closed"; open_mine.updated_at = now(); db.commit()
        s = open_mine
    else:
        v = vehicle_from_qr(db, data.qr_payload)
        # запрет двух открытых смен по одному ТС
        busy = db.query(WorkSession).filter(WorkSession.vehicle_id==v.id, WorkSession.status=="open").first()
        if busy:
            holder = db.query(User).filter(User.id==busy.user_id).first()
            raise HTTPException(409, detail={"code":"VEHICLE_BUSY","holder":{"user_id":holder.id,"full_name":holder.full_name or holder.email}})
        started_ts, used = clamp_ts(data.device_ts, now())
        s = WorkSession(user_id=user.id, vehicle_id=v.id, qr_payload=data.qr_payload,
                        started_at=started_ts, started_city=reverse_city(data.lat, data.lon),
                        started_lat=data.lat, started_lon=data.lon, started_from_device=used, status="open")
        db.add(s); db.commit()
    return {"id": s.id, "user_id": s.user_id, "vehicle_id": s.vehicle_id, "started_at": s.started_at, "ended_at": s.ended_at,
            "status": s.status, "started_city": s.started_city, "ended_city": s.ended_city, "work_minutes": minutes(s)}

@app.get("/me")
def me(user: AuthUser = Depends(require_auth)): return {"id": user.id, "email": user.email, "role": user.role}

@app.get("/me/sessions", response_model=ListSessionsOut)
def my_sessions(user: AuthUser = Depends(require_auth)):
    db = SessionLocal(); rows = db.query(WorkSession).filter(WorkSession.user_id==user.id).order_by(WorkSession.started_at.desc()).all()
    return {"items": [ {"id": r.id, "user_id": r.user_id, "vehicle_id": r.vehicle_id, "started_at": r.started_at, "ended_at": r.ended_at,
                        "status": r.status, "started_city": r.started_city, "ended_city": r.ended_city, "work_minutes": minutes(r)} for r in rows ]}

# admin endpoints (users)
from pydantic import EmailStr
@app.get('/admin/users')
def list_users(admin: AuthUser = Depends(require_admin)):
    db = SessionLocal(); rows = db.query(User).order_by(User.created_at.desc()).all()
    return [{"id":u.id,"email":u.email,"full_name":u.full_name,"role":u.role} for u in rows]

class _CreateUser(AdminUserCreate): pass
@app.post('/admin/users')
def create_user(data: _CreateUser, admin: AuthUser = Depends(require_admin)):
    db = SessionLocal()
    if db.query(User).filter(User.email==str(data.email)).first(): raise HTTPException(400,'Email exists')
    u = User(email=str(data.email), password_hash=make_hash(data.password), role=data.role, full_name=data.full_name or None)
    db.add(u); db.commit(); return {"id":u.id,"email":u.email,"full_name":u.full_name,"role":u.role}

@app.patch('/admin/users/{uid}')
def update_user(uid: str, data: AdminUserUpdate, admin: AuthUser = Depends(require_admin)):
    db = SessionLocal(); u = db.query(User).filter(User.id==uid).first()
    if not u: raise HTTPException(404,'Not found')
    if data.full_name is not None: u.full_name = data.full_name
    if data.role is not None: u.role = data.role
    if data.password: u.password_hash = make_hash(data.password)
    db.commit(); return {"id":u.id,"email":u.email,"full_name":u.full_name,"role":u.role}

SEED_TOKEN = os.getenv("SEED_TOKEN", "change-me")
@app.get("/admin/seed")
def seed_endpoint(token: str):
    if token != SEED_TOKEN: raise HTTPException(403, "Bad token")
    db = SessionLocal()
    if not db.query(User).filter(User.email=="admin@example.com").first():
        db.add(User(email="admin@example.com", password_hash=make_hash("password"), role="admin", full_name="Администратор"))
    for num in ["А123ВС77","B456CD77"]:
        if not db.query(Vehicle).filter(Vehicle.number==num).first(): db.add(Vehicle(number=num, title=f"ТС {num}"))
    db.commit(); return {"ok": True}
