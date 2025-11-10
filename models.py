from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship
import uuid

Base = declarative_base()
def uuid4(): return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=uuid4)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")
    full_name = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    sessions = relationship("WorkSession", back_populates="user")

class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(String, primary_key=True, default=uuid4)
    number = Column(String, unique=True, nullable=False)
    title = Column(String)
    is_active = Column(Boolean, default=True)
    sessions = relationship("WorkSession", back_populates="vehicle")

class WorkSession(Base):
    __tablename__ = "work_sessions"
    id = Column(String, primary_key=True, default=uuid4)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    vehicle_id = Column(String, ForeignKey("vehicles.id"), nullable=False)
    qr_payload = Column(String)
    started_at = Column(DateTime)
    started_city = Column(String)
    started_lat = Column(Float)
    started_lon = Column(Float)
    started_from_device = Column(Boolean, default=False)
    ended_at = Column(DateTime)
    ended_city = Column(String)
    ended_lat = Column(Float)
    ended_lon = Column(Float)
    ended_from_device = Column(Boolean, default=False)
    status = Column(String, nullable=False, default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="sessions")
    vehicle = relationship("Vehicle", back_populates="sessions")
