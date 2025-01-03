from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
# from .config import DATABASE_URL
DATABASE_URL = f"postgresql://{os.getenv('POSTGRESQL_USER')}:{os.getenv('POSTGRESQL_PASSWORD')}@{os.getenv('POSTGRESQL_HOST')}:{os.getenv('POSTGRESQL_PORT')}/{os.getenv('POSTGRESQL_DB')}"

# DATABASE_URL = 'sqlite:///./main_database.db'
# Create the database engine
engine = create_engine(DATABASE_URL, echo=True)

# Base class for models
Base = declarative_base()

# Create a session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Initialize the database
def init_db():
    from models import User  # Import here to avoid circular import
    Base.metadata.create_all(bind=engine)
