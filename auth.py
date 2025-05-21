from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import pyotp
import base64
import qrcode
from io import BytesIO
import hashlib

from models import User, get_db
from kms import create_user_symmetric_key  # ⬅ 引入 KMS 函式

router = APIRouter()


# 密碼雜湊
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# 產生 OTP 密鑰 + QR Code
def generate_otp_secret_and_qr(username: str):
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="StarCSE")
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    qr_data_url = f"data:image/png;base64,{img_str}"
    return secret, qr_data_url


# 註冊
@router.post("/api/register")
async def register(data: dict, db: AsyncSession = Depends(get_db)):
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return JSONResponse(status_code=400, content={"message": "Missing fields"})

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(password)
    otp_secret, qr_code_url = generate_otp_secret_and_qr(username)

    # 產生 user secret key (user_sk)，這邊用 asyncio.create_task 或直接 await
    user_sk = await create_user_symmetric_key(tag=f"user-key-{username}")

    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_pw,
        otp_secret=otp_secret,
        user_sk=user_sk,  # 假設 User 模型有此欄位
    )
    db.add(new_user)
    await db.commit()

    return {"message": "User registered successfully", "qrCodeUrl": qr_code_url}


# 登入
@router.post("/api/login")
async def login(data: dict, db: AsyncSession = Depends(get_db)):
    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if hash_password(password) != user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    totp = pyotp.TOTP(user.otp_secret)
    if not totp.verify(otp):
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    return {"message": "Login successful"}
