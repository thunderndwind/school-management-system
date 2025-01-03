from sqlalchemy import Column, Integer, String, Boolean, Enum
from sqlalchemy.orm import relationship
from database import Base
import enum

class UserRole(str, enum.Enum):
    admin = "admin"
    teacher = "teacher"
    parent = "parent"
    student = "student"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(Enum(UserRole), nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)