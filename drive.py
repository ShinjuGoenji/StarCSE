from fastapi import APIRouter, Depends, Form, HTTPException, File, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import User, Files, UserFiles, get_db
import os
from shutil import rmtree

router = APIRouter()


# Fetching file list for a user
@router.post("/api/files")
async def fetch_file_list(data: dict, db: AsyncSession = Depends(get_db)):
    username = data.get("currentUser")

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    # Get the user based on the provided username
    stmt = select(User).filter(User.username == username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get the files related to the user
    stmt = select(Files).join(UserFiles).filter(UserFiles.user_id == user.id)
    result = await db.execute(stmt)
    files = result.scalars().all()

    # Prepare the response data
    file_list = [
        {"id": file.id, "name": file.file_name, "dir": file.file_dir} for file in files
    ]

    return {"files": file_list}


# Download file by ID
@router.get("/api/files/download")
async def download_file(file_id: int = Form(...), db: AsyncSession = Depends(get_db)):

    # Get the file details from the database
    stmt = select(Files).filter(Files.id == file_id)
    result = await db.execute(stmt)
    file = result.scalar_one_or_none()

    if not file:
        raise HTTPException(status_code=404, detail="File not found, cannot fetch")

    # Path to the file storage (Assuming the files are stored in a directory called 'uploads')
    file_path = os.path.join(file.file_dir)

    # Check if file exists
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"{file_path} not found on server")

    # Return the file as a response
    return FileResponse(file_path, filename=file.file_name)


# Delete file by ID
@router.delete("/api/files/delete")
async def delete_file(file_id: int = Form(...), db: AsyncSession = Depends(get_db)):

    # Get the file details from the database
    stmt = select(Files).filter(Files.id == file_id)
    result = await db.execute(stmt)
    file = result.scalar_one_or_none()

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # Delete the file record from the database
    await db.delete(file)
    await db.commit()

    # Path to the file storage (Assuming the files are stored in a directory called 'uploads')
    file_path = os.path.join(file.file_dir)

    # Delete the actual file from the storage
    if os.path.exists(file_path):
        os.remove(file_path)
    else:
        raise HTTPException(status_code=404, detail="File deletion failed")

    return {"message": "File deleted successfully"}
