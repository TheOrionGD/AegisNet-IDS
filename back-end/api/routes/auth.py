from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorDatabase
from ..models.database import get_database
from ..auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    UserResponse,
    Token,
    get_password_hash,
)
from ..auth import UserCreate

router = APIRouter()


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Authenticate user and return JWT token."""
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user.get("role", "viewer")},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """Get current user information."""
    return UserResponse(
        id=str(current_user.get("_id", "")),
        username=current_user.get("username", ""),
        email=current_user.get("email"),
        role=current_user.get("role", "viewer"),
        is_active=current_user.get("is_active", True),
    )


@router.post("/users/", response_model=UserResponse)
async def create_user(
    user: UserCreate, db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Create a new user."""
    try:
        users_collection = db["users"]
        existing = await users_collection.find_one({"username": user.username})
        if existing:
            raise HTTPException(status_code=400, detail="Username already registered")

        hashed_password = get_password_hash(user.password)
        user_doc = {
            "username": user.username,
            "email": user.email,
            "password_hash": hashed_password,
            "role": user.role,
            "is_active": True,
        }
        result = await users_collection.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return UserResponse(
            id=str(user_doc["_id"]),
            username=user_doc["username"],
            email=user_doc["email"],
            role=user_doc["role"],
            is_active=user_doc["is_active"],
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
