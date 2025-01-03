# schemas.py (Pydantic Schema)
from pydantic import BaseModel
from enum import Enum
from typing import Optional
from pydantic import EmailStr

# Enum for UserRole
class UserRole(str, Enum):
    admin = "admin"
    teacher = "teacher"
    parent = "parent"
    student = "student"

# Base schema for User data (used for creating and displaying users)
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: UserRole
    first_name: str
    last_name: str

# Schema used for returning user data after querying
class UserOut(UserBase):
    id: int
    is_active: bool
    is_verified: bool

    class Config:
        orm_mode = True  # This allows Pydantic to work with SQLAlchemy models

# Schema used when creating a new user (includes password)
class UserCreate(UserBase):
    password: str
    email: EmailStr  # This will automatically validate email format.


# Schema used when updating user data (optional fields)
class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    password: Optional[str] = None
