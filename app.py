from flask import Flask, request, jsonify, send_from_directory
import os

app = Flask(__name__)
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")

# 確保資料夾存在
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)


@app.route("/")
def serve_index():
    return send_from_directory("static", "index.html")


@app.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    return handle_file_action("encrypt")


@app.route("/api/decrypt", methods=["POST"])
def decrypt_file():
    return handle_file_action("decrypt")


def handle_file_action(action):
    if "files" not in request.files:
        return jsonify({"error": "No files part"}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files uploaded"}), 400

    saved_files = []
    folder = ENCRYPT_FOLDER if action == "encrypt" else DECRYPT_FOLDER

    for file in files:
        if file.filename == "":
            continue
        filepath = os.path.join(folder, file.filename)
        file.save(filepath)
        saved_files.append(file.filename)

    if not saved_files:
        return jsonify({"error": "No valid files uploaded"}), 400

    return jsonify(
        {
            "message": f"{action.capitalize()}ed files saved successfully.",
            "files": saved_files,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
