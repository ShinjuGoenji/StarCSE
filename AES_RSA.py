import base64
from io import BytesIO
import json
import subprocess
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
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from models import User, get_db

#################################################
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


#################################################
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


# async def decrypt_files_with_AES_turbo(
#     file: bytes, filename: str, iv_file: bytes, AES_key: bytes
# ):
#     key_hex = AES_key.hex().upper()
#     base_dir = "./hal/aes_dec"
#     cipher_in_dir = os.path.join(base_dir, "cipher_in")
#     iv_in_dir = os.path.join(base_dir, "iv_in")
#     plain_out_dir = os.path.join(base_dir, "plain_out")

#     os.makedirs(cipher_in_dir, exist_ok=True)
#     os.makedirs(iv_in_dir, exist_ok=True)
#     os.makedirs(plain_out_dir, exist_ok=True)

#     iv_filename = filename + "_iv.txt"
#     cipher_path = os.path.join(cipher_in_dir, filename)
#     iv_path = os.path.join(iv_in_dir, iv_filename)
#     plain_filename = filename[:-8] if filename.endswith("_enc.bin") else filename
#     plain_path = os.path.join(plain_out_dir, plain_filename)

#     # 儲存 ciphertext
#     with open(cipher_path, "wb") as f:
#         f.write(file)

#     # 儲存 iv
#     with open(iv_path, "wb") as f:
#         f.write(iv_file)

#     # 執行解密命令
#     cmd = f"./aes_dec {key_hex} {filename} {plain_filename}"
#     try:
#         subprocess.run(
#             cmd,
#             shell=True,
#             cwd=base_dir,
#             check=True,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#         )
#     except subprocess.CalledProcessError as e:
#         raise RuntimeError(
#             f"Decryption failed: ./aes_dec {key_hex} {filename} {plain_filename} {e.stderr.decode()}"
#         )

#     # 讀取解密後內容
#     with open(plain_path, "rb") as f:
#         plain_data = f.read()

#     return {
#         "filename": plain_filename,
#         "content": plain_data,
#     }


# async def encrypt_files_with_AES_turbo(files: List[UploadFile], AES_key: bytes):
#     key_hex = AES_key.hex().upper()
#     base_dir = "./hal/aes_enc"
#     plain_in_dir = os.path.join(base_dir, "plain_in")
#     cipher_out_dir = os.path.join(base_dir, "cipher_out")
#     iv_out_dir = os.path.join(base_dir, "iv_out")

#     encrypted_files = []

#     os.makedirs(plain_in_dir, exist_ok=True)
#     os.makedirs(cipher_out_dir, exist_ok=True)
#     os.makedirs(iv_out_dir, exist_ok=True)

#     for file in files:
#         filename = file.filename
#         plain_path = os.path.join(plain_in_dir, filename)
#         cipher_filename = filename + "_enc.bin"
#         cipher_path = os.path.join(cipher_out_dir, cipher_filename)
#         iv_filename = cipher_filename + "_iv.txt"
#         iv_path = os.path.join(iv_out_dir, iv_filename)

#         # 儲存 plaintext
#         with open(plain_path, "wb") as f:
#             content = await file.read()
#             f.write(content)

#         # 執行加密命令
#         cmd = f"./aes_enc {key_hex} {filename} {cipher_filename}"
#         try:
#             subprocess.run(
#                 cmd,
#                 shell=True,
#                 cwd=base_dir,
#                 check=True,
#                 stdout=subprocess.PIPE,
#                 stderr=subprocess.PIPE,
#             )
#         except subprocess.CalledProcessError as e:
#             raise RuntimeError(f"Encryption failed: {e.stderr.decode()}")

#         # 讀取加密後內容與 IV
#         with open(cipher_path, "rb") as f:
#             cipher_data = f.read()
#         with open(iv_path, "rb") as f:
#             iv_data = f.read()

#         encrypted_files.append(
#             {
#                 "filename": cipher_filename,
#                 "content": cipher_data,
#                 "iv_filename": iv_filename,
#                 "iv_content": iv_data,
#             }
#         )

#     return encrypted_files
