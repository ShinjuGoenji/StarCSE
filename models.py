from sqlalchemy import Column, Integer, String, Table, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, relationship
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_async_engine(DATABASE_URL, echo=True)
Base = declarative_base()
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


user_files = Table(
    "user_files",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("file_id", Integer, ForeignKey("files.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    otp_secret = Column(String(32), nullable=False)
    user_sk = Column(String, nullable=True)
    user_pk = Column(String, nullable=True)

    # 用戶和檔案之間的關聯
    files = relationship("Files", secondary=user_files, back_populates="users")


class Files(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, nullable=False)
    file_dir = Column(String, nullable=False)

    # 檔案和用戶之間的關聯
    users = relationship("User", secondary=user_files, back_populates="files")


async def get_db():
    async with async_session() as session:
        yield session
