import os, time, jwt
from passlib.hash import bcrypt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_TTL = 60 * 60 * 12
security = HTTPBearer()

class AuthUser:
    def __init__(self, id: str, email: str, role: str):
        self.id = id; self.email = email; self.role = role

def make_hash(pwd: str): return bcrypt.hash(pwd)
def verify_pwd(pwd: str, h: str): return bcrypt.verify(pwd, h)

def mint_token(user_id: str, email: str, role: str):
    now = int(time.time())
    return jwt.encode({"sub": user_id, "email": email, "role": role, "iat": now, "exp": now + JWT_TTL}, JWT_SECRET, algorithm="HS256")

def require_auth(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        p = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        return AuthUser(p["sub"], p["email"], p.get("role","user"))
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except Exception:
        raise HTTPException(401, "Invalid token")

def require_admin(user: AuthUser = Depends(require_auth)):
    if user.role != "admin": raise HTTPException(403, "Admin only")
    return user
