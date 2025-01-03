from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError
from sqlalchemy.orm import Session
from models import User
from schemas import UserCreate, UserUpdate, UserOut
from utils import decode_token, hash_password, verify_role, validate_password
from fastapi_limiter.depends import RateLimiter
from database import SessionLocal
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

router = APIRouter(prefix="/admin")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Route to create a user (with role validation)
@router.post("/create_user", response_model=UserOut)
async def create_user(
    user: UserCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    # rate_limit: bool = Depends(RateLimiter(times=5, seconds=600))
    ):

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired or is invalid")

    if not payload:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials")
    
    current_user = db.query(User).filter(User.username == payload.get("sub")).first()

    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    verify_role(current_user, "admin")

    # if user.role == "admin" and current_user.role != "admin":
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin can assign the admin role")

    db_user_by_username = db.query(User).filter(User.username == user.username).first()
    if db_user_by_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    
    db_user_by_email = db.query(User).filter(User.email == user.email).first()
    if db_user_by_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")


    # Validate password strength
    validate_password(user.password)
    
    # Hash the password before saving
    hashed_password = hash_password(user.password)

    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role,
        first_name=user.first_name,
        last_name=user.last_name
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user

# Route to update user information
@router.put("/update_user/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int, 
    user: UserUpdate, 
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)):

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired or is invalid")

    if not payload:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials")
    
    current_user = db.query(User).filter(User.username == payload.get("sub")).first()

    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    verify_role(current_user, "admin")

    db_user_by_username = db.query(User).filter(User.username == user.username).first()
    if db_user_by_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    
    db_user_by_email = db.query(User).filter(User.email == user.email).first()
    if db_user_by_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    db_user = db.query(User).filter(User.id == user_id).first()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.first_name:
        db_user.first_name = user.first_name
    if user.last_name:
        db_user.last_name = user.last_name
    if user.email:
        db_user.email = user.email
    if user.password:
        validate_password(user.password)
        db_user.hashed_password = hash_password(user.password)
    if user.role:
        db_user.role = user.role

    db.commit()
    db.refresh(db_user)

    return db_user

# Route to delete a user
@router.delete("/delete_user/{user_id}", status_code=204)
async def delete_user(
    user_id: int, 
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)):

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired or is invalid")

    if not payload:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials")
    
    current_user = db.query(User).filter(User.username == payload.get("sub")).first()

    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    verify_role(current_user, "admin")

    db_user = db.query(User).filter(User.id == user_id).first()
    
    
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()

    return {"message": "User deleted successfully"}
