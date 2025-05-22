import base64
from io import BytesIO
import json
import zipfile
from fastapi import FastAPI, Form, Request, UploadFile, File, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from typing import List
import shutil
import os
from sqlalchemy import Tuple, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Base, engine
from auth import router as auth_router

import kms
from models import User, get_db

#################################################
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

#################################################

# FastAPI app init
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# File paths
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)

# Register auth router
app.include_router(auth_router)


# Create tables
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def extract_user_keys(user_key_id: str) -> bytes:
    with open(f"user_keys/user_sk/{user_key_id}.json", "r") as f:
        user_sk_json = json.load(f)

    try:
        key_material = None
        for item in user_sk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_sk = bytes.fromhex(key_material)
    except:
        return None

    with open(f"user_keys/user_pk/{user_key_id}_pk.json", "r") as f:
        user_pk_json = json.load(f)

    try:
        key_material = None
        for item in user_pk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_pk = bytes.fromhex(key_material)
    except:
        return None

    return user_pk, user_sk


async def get_user_keys(username: str, db: AsyncSession):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Username not found")
    user_pk = bytes.fromhex(user.user_pk)
    user_sk = bytes.fromhex(user.user_sk)

    return user_pk, user_sk


async def encrypt_files_with_AES(files: List[UploadFile], AES_key: bytes):
    encrypted_files = []
    for file in files:
        content = await file.read()

        # AES-GCM 加密
        nonce = os.urandom(12)
        aesgcm = AESGCM(AES_key)
        encrypted = aesgcm.encrypt(nonce, content, associated_data=None)
        encrypted_data = nonce + encrypted

        # 加密檔案命名：原檔名 + .enc
        filename = file.filename + ".enc"

        encrypted_files.append({"filename": filename, "content": encrypted_data})

    return encrypted_files


def sign_encrypted_files(
    user_sk: bytes,
    encrypted_files: list,
) -> list:
    private_key = load_der_private_key(user_sk, password=None)

    signatures = []

    for file in encrypted_files:
        encrypted_data = file["content"]
        filename = file["filename"]

        signature = private_key.sign(
            encrypted_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        # 儲存 filename 與對應簽章 (base64 編碼可讀性更好)
        signatures.append(
            {
                "filename": filename,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        )

    return signatures


def encrypt_AES_key(AES_key: bytes, user_pk: bytes) -> bytes:
    public_key = serialization.load_der_public_key(user_pk, backend=default_backend())

    AES_key_enc = public_key.encrypt(
        AES_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AES_key_enc


@app.post("/api/encrypt")
async def encrypt_files(
    username: str = Form(...),
    recipients: str = Form(...),  # JSON 字串形式的使用者名稱清單
    files: List[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    recipient_list = json.loads(recipients)
    all_recipients = [username] + recipient_list  # 包含自己

    # 1. 產生 AES 金鑰
    AES_key: bytes = kms.generate_AES_key()

    # 2. 加密檔案
    encrypted_files: List[dict] = await encrypt_files_with_AES(
        files=files, AES_key=AES_key
    )
    # dict 結構: {"filename": "file.txt", "content": b"...encrypted..."}

    # 3. 取得簽名用的金鑰
    user_pk, user_sk = await get_user_keys(username=username, db=db)
    signatures: List[dict] = sign_encrypted_files(
        user_sk=user_sk, encrypted_files=encrypted_files
    )
    # dict 結構: {"filename": ..., "signature": ...}

    # 4. 為每位共享者建立一份獨立的 ZIP 包（含專屬的 AES key 加密）
    outer_zip_buffer = BytesIO()
    with zipfile.ZipFile(outer_zip_buffer, "w", zipfile.ZIP_DEFLATED) as outer_zip:
        for recipient in all_recipients:
            recipient_pk, _ = await get_user_keys(username=recipient, db=db)
            enc_AES_key = encrypt_AES_key(AES_key, recipient_pk)

            # 建立該 recipient 的子 ZIP
            sub_zip_buffer = BytesIO()
            with zipfile.ZipFile(sub_zip_buffer, "w", zipfile.ZIP_DEFLATED) as sub_zip:
                for file in encrypted_files:
                    sub_zip.writestr(file["filename"], file["content"])

                sub_zip.writestr("signatures.json", json.dumps(signatures, indent=2))
                sub_zip.writestr(f"aes_key-{recipient}.enc", enc_AES_key)

            sub_zip_buffer.seek(0)
            outer_zip.writestr(f"{recipient}.zip", sub_zip_buffer.read())

    outer_zip_buffer.seek(0)
    return StreamingResponse(
        outer_zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": f"attachment; filename=encrypted_packages.zip"},
    )


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
