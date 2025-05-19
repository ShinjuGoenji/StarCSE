from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, EmailStr
from typing import List
from dotenv import load_dotenv
import pyotp
import base64
import qrcode
from io import BytesIO
import os
import shutil
import hashlib

# Load environment
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# SQLAlchemy async setup
engine = create_async_engine(DATABASE_URL, echo=True)
Base = declarative_base()
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# FastAPI init
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Upload folders
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)


# DB Model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    otp_secret = Column(String(32), nullable=False)


# Create tables (run once on startup)
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Pydantic schemas
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str
    otp: str


# Hash password
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# Generate OTP and QR code
def generate_otp_secret_and_qr(username: str):
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="StarCSE")
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    qr_data_url = f"data:image/png;base64,{img_str}"
    return secret, qr_data_url


# Dependency: DB session
async def get_db():
    async with async_session() as session:
        yield session


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/register")
async def register(data: dict, db: AsyncSession = Depends(get_db)):
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    # 檢查是否已有帳號
    result = await db.execute(User.__table__.select().where(User.username == username))
    user = result.scalar()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # 建立帳號
    hashed_pw = hash_password(password)
    otp_secret, qr_code_url = generate_otp_secret_and_qr(username)
    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_pw,
        otp_secret=otp_secret,
    )
    db.add(new_user)
    await db.commit()

    return {"message": "User registered successfully", "qrCodeUrl": qr_code_url}


@app.post("/api/login")
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        User.__table__.select().where(User.username == data.username)
    )
    user = result.scalar()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if hash_password(data.password) != user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    totp = pyotp.TOTP(user.otp_secret)
    if not totp.verify(data.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    return {"message": "Login successful"}


@app.post("/api/encrypt")
async def encrypt_files(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    saved_files = []
    for file in files:
        file_location = os.path.join(ENCRYPT_FOLDER, file.filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        saved_files.append(file.filename)
    return {"message": "Encrypted files saved successfully", "files": saved_files}


@app.post("/api/decrypt")
async def decrypt_files(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    saved_files = []
    for file in files:
        file_location = os.path.join(DECRYPT_FOLDER, file.filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        saved_files.append(file.filename)
    return {"message": "Decrypted files saved successfully", "files": saved_files}
