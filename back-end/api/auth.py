import os
import bcrypt
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorDatabase
from .models.database import get_database

logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "your-jwt-secret-key":
    # In production, we MUST have a secure key
    if os.getenv("ENVIRONMENT") == "production":
        logger.critical(
            "PRODUCTION_FAILURE: Insecure JWT_SECRET_KEY detected. System will NOT start."
        )
        raise ValueError("JWT_SECRET_KEY must be set to a secure value in production.")
    else:
        logger.warning(
            "INSECURE_SECRET: Using default JWT secret. Setting JWT_SECRET_KEY environment variable is strongly recommended."
        )
        SECRET_KEY = os.getenv(
            "JWT_SECRET_KEY", "cns_dev_fallback_secret_keep_it_secure_in_prod"
        )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    role: str = "viewer"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: str
    is_active: bool = True

    class Config:
        from_attributes = True


def verify_password(plain_password, hashed_password):
    if isinstance(plain_password, str):
        plain_password = plain_password.encode("utf-8")
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode("utf-8")
    try:
        return bcrypt.checkpw(plain_password, hashed_password)
    except Exception:
        return False


def get_password_hash(password):
    if isinstance(password, str):
        password = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt).decode("utf-8")


async def authenticate_user(db: AsyncIOMotorDatabase, username: str, password: str):
    user_doc = await db["users"].find_one({"username": username})
    if not user_doc:
        return None
    if not verify_password(password, user_doc.get("password_hash", "")):
        return None
    return user_doc


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
    return token_data


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials
    token_data = verify_token(token, credentials_exception)

    user_doc = await db["users"].find_one({"username": token_data.username})
    if user_doc is None:
        raise credentials_exception
    return user_doc


class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    async def __call__(self, user: dict = Depends(get_current_user)):
        user_role = user.get("role", "viewer")
        if user_role not in self.allowed_roles:
            logger.warning(
                f"UNAUTHORIZED_ACCESS: User {user.get('username')} (Role: {user_role}) attempted to access role-restricted resource."
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role: {user_role}",
            )
        return user


# Role Dependencies
require_admin = RoleChecker(["admin"])
require_analyst = RoleChecker(["admin", "analyst"])
require_viewer = RoleChecker(["admin", "analyst", "viewer"])
