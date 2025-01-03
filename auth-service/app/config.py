import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/auth_db")

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Expiry time for the JWT tokens
REFRESH_TOKEN_EXPIRE_DAYS = 7    # Expiry time for the refresh token
