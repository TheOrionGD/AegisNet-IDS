from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
from fastapi import HTTPException
import logging
import os
from dotenv import load_dotenv
from pathlib import Path
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env", override=False)

MONGODB_URL = os.environ.get(
    "MONGODB_URL",
    "mongodb+srv://aegisnet:aegisnet@aegisnet.rzqvn80.mongodb.net/?appName=AegisNET",
)
DATABASE_NAME = os.environ.get("DATABASE_NAME", "aegisnet")


class Database:
    client: AsyncIOMotorClient = None
    db = None


db_instance = Database()


async def connect_to_mongo():
    """Connect to MongoDB Atlas"""
    try:
        db_instance.client = AsyncIOMotorClient(MONGODB_URL)
        await db_instance.client.admin.command("ping")
        db_instance.db = db_instance.client[DATABASE_NAME]
        logger.info("Connected to MongoDB Atlas")
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB Atlas: {e}")
        raise


async def close_mongo_connection():
    """Close MongoDB connection"""
    if db_instance.client:
        db_instance.client.close()
        logger.info("Disconnected from MongoDB Atlas")


def get_database():
    """Get database instance"""
    if db_instance.db is None:
        raise HTTPException(
            status_code=503, detail="Database not initialized. Please try again."
        )
    return db_instance.db


class Feedback(BaseModel):
    id: str
    incident_id: str
    label: str
    analyst: str
    notes: Optional[str] = ""


class ModelVersion(BaseModel):
    version: str
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    training_samples: Optional[int] = None
    trained_at: Optional[str] = None


class ResponseAction(BaseModel):
    id: str
    incident_id: str
    action_type: str
    target: Optional[str] = None
    status: Optional[str] = "pending"
    executed_at: Optional[str] = None


class RuleScore(BaseModel):
    sid: int
    hit_count: int = 0
    effectiveness_score: float = 0.0
    is_retired: bool = False
    last_hit_at: Optional[str] = None
