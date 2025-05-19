import base64
import bcrypt
import pyotp
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    status,
    UploadFile,
    File,
    Form,
    Request,
)
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from db import Base, User
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 讀取 .env 檔案
load_dotenv()

# 取得環境變數
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

app = FastAPI()

# CORS 設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 改為你的前端網址會更安全
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 靜態檔案與模板
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Pydantic schemas
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str
    otp: str


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.post("/api/register")
async def register(user: UserRegister, request: Request):
    print(await request.json())
    async with async_session() as session:
        exists_username = await session.execute(
            select(User).where(User.username == user.username)
        )
        if exists_username.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists",
            )

        exists_email = await session.execute(
            select(User).where(User.email == user.email)
        )
        if exists_email.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        hashed_password = bcrypt.hashpw(
            user.password.encode(), bcrypt.gensalt()
        ).decode()
        otp_secret = pyotp.random_base32()

        new_user = User(
            username=user.username,
            email=user.email,
            password_hash=hashed_password,
            otp_secret=otp_secret,
            is_active=True,
        )
        session.add(new_user)
        await session.commit()

        totp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
            name=user.username, issuer_name="StarCSE"
        )
        qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?data={totp_uri}"

        return {"message": "User registered successfully", "qrCodeUrl": qr_code_url}


@app.post("/api/login")
async def login(user: UserLogin):
    async with async_session() as session:
        result = await session.execute(
            select(User).where(User.username == user.username)
        )
        db_user = result.scalars().first()
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect username or password",
            )

        if not bcrypt.checkpw(user.password.encode(), db_user.password_hash.encode()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect username or password",
            )

        totp = pyotp.TOTP(db_user.otp_secret)
        if not totp.verify(user.otp):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP code"
            )

        return {"message": "Login successful"}


# --- 加密 API ---
@app.post("/api/encrypt")
async def encrypt_files(files: list[UploadFile] = File(...)):
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)

    encrypted_results = []
    nonce = os.urandom(12)

    for file in files:
        data = await file.read()
        encrypted = aesgcm.encrypt(nonce, data, None)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        encrypted_results.append(
            {"filename": file.filename + ".enc", "content": encrypted_b64}
        )

    key_b64 = base64.b64encode(key).decode()
    nonce_b64 = base64.b64encode(nonce).decode()

    return {
        "key": key_b64,
        "nonce": nonce_b64,
        "files": encrypted_results,
        "message": "Files encrypted successfully",
    }


# --- 解密 API ---
@app.post("/api/decrypt")
async def decrypt_files(
    key: str = Form(...), nonce: str = Form(...), files: list[UploadFile] = File(...)
):
    key_bytes = base64.b64decode(key)
    nonce_bytes = base64.b64decode(nonce)
    aesgcm = AESGCM(key_bytes)

    decrypted_results = []

    for file in files:
        encrypted_data_b64 = await file.read()
        encrypted_data = base64.b64decode(encrypted_data_b64)
        try:
            decrypted = aesgcm.decrypt(nonce_bytes, encrypted_data, None)
        except Exception:
            raise HTTPException(
                status_code=400, detail=f"Failed to decrypt file {file.filename}"
            )

        decrypted_results.append(
            {
                "filename": file.filename.replace(".enc", ".dec"),
                "content": base64.b64encode(decrypted).decode(),
            }
        )

    return {"files": decrypted_results, "message": "Files decrypted successfully"}
