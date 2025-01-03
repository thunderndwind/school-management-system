from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from database import SessionLocal
from models import User
from utils import hash_password, verify_password, create_access_token, create_refresh_token, decode_token, validate_password, verify_role
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis

# Initialize Redis client using redis-py
redis_client = redis.from_url("redis://localhost:6379", decode_responses=True)

# Initialize FastAPI rate limiter
limiter = RateLimiter()

# OAuth2 Password Bearer to get the token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

async def init_limiter():
    await FastAPILimiter.init(redis_client)

router = APIRouter(prefix="/auth")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Route to login and get both access and refresh tokens
@router.post("/login")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db),
    # rate_limit: bool = Depends(RateLimiter(times=3, seconds=600))  # Rate Limiting as a Dependency
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    refresh_token = create_refresh_token(data={"sub": user.username, "role": user.role})

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# Route to refresh the access token using a refresh token
@router.post("/refresh")
async def refresh_access_token(
    refresh_token: str, 
    db: Session = Depends(get_db),
    rate_limit: bool = Depends(RateLimiter(times=2, seconds=3600))  # Rate Limiting as a Dependency
):
    payload = decode_token(refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    new_access_token = create_access_token(data={"sub": user.username, "role": user.role})

    return {"access_token": new_access_token, "token_type": "bearer"}

# Route to add a new admin (only accessible by an existing admin)
@router.post("/create_admin", status_code=status.HTTP_201_CREATED)
async def create_admin(
    username: str, 
    password: str, 
    email: str, 
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db),
    rate_limit: bool = Depends(RateLimiter(times=1, seconds=3600))  # Optional Rate Limiting for this route
):
    # Decode token to identify the current user
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials")

    current_user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Ensure the current user has admin privileges
    verify_role(current_user, "admin")

    # Validate password strength
    validate_password(password)

    hashed_password = hash_password(password)

    new_user = User(username=username, email=email, hashed_password=hashed_password, role="admin")
    db.add(new_user)
    db.commit()

    return {"message": "Admin created successfully"}
