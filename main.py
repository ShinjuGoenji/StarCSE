from pydantic import BaseModel, EmailStr
from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import List
import os
import shutil
import hashlib
from dotenv import load_dotenv
import pyotp
import base64
import qrcode
from io import BytesIO

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI()

# 靜態資源、模板
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# 檔案資料夾
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)


# 模擬用「資料庫」：字典形式存帳號資訊（實務要用真DB）
users_db = {}


# Pydantic schemas
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str
    otp: str


# 工具：密碼雜湊（SHA256）
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# 工具：產生 Google Authenticator 秘鑰和 QR Code URL
def generate_otp_secret_and_qr(username: str):
    secret = pyotp.random_base32()
    # 產生 provisioning URI
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="StarCSE")
    # 產生 QR code 圖片
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    qr_data_url = f"data:image/png;base64,{img_str}"
    return secret, qr_data_url


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/register")
async def register(data: dict):
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return JSONResponse(status_code=400, content={"message": "Missing fields"})

    if username in users_db:
        return JSONResponse(
            status_code=400, content={"message": "Username already exists"}
        )

    hashed_pw = hash_password(password)
    otp_secret, qr_code_url = generate_otp_secret_and_qr(username)

    # 儲存使用者資料（含 OTP secret）
    users_db[username] = {
        "email": email,
        "password_hash": hashed_pw,
        "otp_secret": otp_secret,
    }

    return {"message": "User registered successfully", "qrCodeUrl": qr_code_url}


@app.post("/api/login")
async def login(data: dict):
    username = data.get("username")
    password = data.get("password")
    otp_code = data.get("otp")

    if not username or not password or not otp_code:
        return JSONResponse(status_code=400, content={"message": "Missing fields"})

    user = users_db.get(username)
    if not user:
        return JSONResponse(
            status_code=401, content={"message": "Invalid username or password"}
        )

    hashed_pw = hash_password(password)
    if hashed_pw != user["password_hash"]:
        return JSONResponse(
            status_code=401, content={"message": "Invalid username or password"}
        )

    totp = pyotp.TOTP(user["otp_secret"])
    if not totp.verify(otp_code):
        return JSONResponse(status_code=401, content={"message": "Invalid OTP code"})

    # 登入成功
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
