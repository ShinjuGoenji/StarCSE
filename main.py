from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
from typing import List

app = FastAPI()

# 掛載 static 資料夾（供前端使用）
app.mount("/static", StaticFiles(directory="static"), name="static")

# 設定模板資料夾
templates = Jinja2Templates(directory="templates")

# 建立加解密的檔案資料夾
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/encrypt")
async def encrypt_files(files: List[UploadFile] = File(...)):
    return await handle_file_action(files, "encrypt")


@app.post("/api/decrypt")
async def decrypt_files(files: List[UploadFile] = File(...)):
    return await handle_file_action(files, "decrypt")


async def handle_file_action(files: List[UploadFile], action: str):
    if not files:
        return JSONResponse(content={"error": "No files uploaded"}, status_code=400)

    saved_files = []
    folder = ENCRYPT_FOLDER if action == "encrypt" else DECRYPT_FOLDER

    for file in files:
        if not file.filename:
            continue
        file_path = os.path.join(folder, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())
        saved_files.append(file.filename)

    if not saved_files:
        return JSONResponse(
            content={"error": "No valid files uploaded"}, status_code=400
        )

    return JSONResponse(
        content={
            "message": f"{action.capitalize()}ed files saved successfully.",
            "files": saved_files,
        }
    )


# from flask import Flask, request, jsonify, send_from_directory
# import os

# app = Flask(__name__)
# BASE_UPLOAD_FOLDER = "uploads"
# ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
# DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")

# os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
# os.makedirs(DECRYPT_FOLDER, exist_ok=True)


# @app.route("/")
# def serve_index():
#     return send_from_directory("static", "index.html")


# @app.route("/api/encrypt", methods=["POST"])
# def encrypt_file():
#     return handle_file_action("encrypt")


# @app.route("/api/decrypt", methods=["POST"])
# def decrypt_file():
#     return handle_file_action("decrypt")


# def handle_file_action(action):
#     if "files" not in request.files:
#         return jsonify({"error": "No files part"}), 400

#     files = request.files.getlist("files")
#     if not files:
#         return jsonify({"error": "No files uploaded"}), 400

#     saved_files = []
#     folder = ENCRYPT_FOLDER if action == "encrypt" else DECRYPT_FOLDER

#     for file in files:
#         if file.filename == "":
#             continue
#         filepath = os.path.join(folder, file.filename)
#         file.save(filepath)
#         saved_files.append(file.filename)

#     if not saved_files:
#         return jsonify({"error": "No valid files uploaded"}), 400

#     return jsonify(
#         {
#             "message": f"{action.capitalize()}ed files saved successfully.",
#             "files": saved_files,
#         }
#     )


# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
