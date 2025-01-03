from fastapi import FastAPI
from routes import auth , user_management
from database import init_db, SessionLocal

app = FastAPI()

@app.on_event("startup")
async def startup():
    # Initialize the limiter
    await auth.init_limiter()
    init_db()


app.include_router(auth.router)
app.include_router(user_management.router)

@app.get("/hello")
def read_root():
    return {"message": "Hello, World!"}
