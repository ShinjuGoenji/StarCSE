import pytest
from fastapi.testclient import TestClient
from main import app  # 改成你的 FastAPI app import

client = TestClient(app)


def test_encrypt_files():
    username = "test"  # 測試用使用者
    filepath = "test.txt"  # 測試檔案

    with open(filepath, "rb") as f:
        files = {
            "files": ("test.txt", f, "text/plain"),
            # 如果是多檔案，可以用列表: [("files", (filename, fileobj, content_type))]
        }
        data = {
            "username": username,
        }

        response = client.post("/api/encrypt", data=data, files=files)

    assert response.status_code == 200
    # 改為儲存 zip 內容到檔案，或直接解析 zip：
    with open("test_output.zip", "wb") as f:
        f.write(response.content)

    # # 檢查回傳格式，這裡你可依實際回傳調整
    # assert "files" in json_data
    # assert isinstance(json_data["files"], list)
    # assert len(json_data["files"]) > 0
