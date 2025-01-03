from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
from models import User
from config import DATABASE_URL
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError

# Set up password hashing (same as in your main code)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to hash a password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Set up the database engine and session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create the tables if they do not exist
Base.metadata.create_all(bind=engine)

# Function to add an admin user
def add_admin(username: str, password: str, email: str, first_name: str, last_name: str):
    db = SessionLocal()
    try:
        # Check if user already exists (to avoid duplicates)
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            print(f"User with email {email} already exists!")
            return

        # Hash the password
        hashed_password = hash_password(password)

        # Create the admin user
        admin_user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            role="admin",  # Assigning role as 'admin'
            is_active=True,
            is_verified=True,
            first_name=first_name,  # Provide first_name
            last_name=last_name     # Provide last_name
        )

        # Add the user to the session and commit
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        print(f"Admin {username} added successfully!")

    except IntegrityError as e:
        db.rollback()  # Rollback transaction on error
        print(f"Error occurred: {str(e)}")
    finally:
        db.close()


# Example usage: Adding an admin user
if __name__ == "__main__":
    add_admin("admin_user", "admin_password", "admin@example.com", "Admin", "User")
