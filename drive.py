from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import User, Files, user_files, get_db
import os

router = APIRouter()


# Fetch file list
@router.post("/api/files")
async def fetch_file_list(data: dict, db: AsyncSession = Depends(get_db)):
    username = data.get("currentUser")
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stmt = select(Files).join(user_files).where(user_files.c.user_id == user.id)
    result = await db.execute(stmt)
    files = result.scalars().all()

    return {
        "files": [{"id": f.id, "name": f.file_name, "dir": f.file_dir} for f in files]
    }


# Download file by file ID
@router.get("/api/files/download")
async def download_file(data: dict, db: AsyncSession = Depends(get_db)):
    file_id = data.get("fileId")

    stmt = select(Files).where(Files.id == file_id)
    result = await db.execute(stmt)
    file = result.scalar_one_or_none()

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = os.path.join(file.file_dir)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server")

    return FileResponse(file_path, filename=file.file_name)


# Delete file by file ID
@router.delete("/api/files/delete")
async def delete_file(data: dict, db: AsyncSession = Depends(get_db)):
    file_id = data.get("fileId")

    stmt = select(Files).where(Files.id == file_id)
    result = await db.execute(stmt)
    file = result.scalar_one_or_none()

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # Remove association in user_files
    await db.execute(user_files.delete().where(user_files.c.file_id == file_id))

    # Delete file record
    await db.delete(file)
    await db.commit()

    file_path = os.path.join(file.file_dir)
    if os.path.exists(file_path):
        os.remove(file_path)

    return {"message": "File deleted successfully"}
