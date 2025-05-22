import pytest
from httpx import AsyncClient
from main import app
from asgi_lifespan import LifespanManager


@pytest.mark.asyncio
async def test_register_success():
    test_user = {
        "username": "testuser1",
        "password": "testpass123",
        "email": "test1@example.com",
    }

    async with LifespanManager(app):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/api/register", json=test_user)
            assert response.status_code == 200
            assert "qrCodeUrl" in response.json()


@pytest.mark.asyncio
async def test_register_duplicate_username():
    test_user = {
        "username": "testuser1",  # 假設已經存在
        "password": "testpass123",
        "email": "another@example.com",
    }

    async with LifespanManager(app):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/api/register", json=test_user)
            assert response.status_code == 400
            assert response.json()["detail"] == "Username already exists"


@pytest.mark.asyncio
async def test_register_missing_fields():
    test_user = {"username": "", "password": "somepass", "email": "missing@example.com"}

    async with LifespanManager(app):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/api/register", json=test_user)
            assert response.status_code == 400
            assert response.json()["message"] == "Missing fields"
