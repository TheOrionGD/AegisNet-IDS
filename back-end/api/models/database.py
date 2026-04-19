from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
import logging

logger = logging.getLogger(__name__)

# MongoDB Atlas connection string
MONGODB_URL = "mongodb+srv://aegisnet:aegisnet@aegisnet.rzqvn80.mongodb.net/?appName=AegisNET"

# Database name
DATABASE_NAME = "aegisnet"

class Database:
    client: AsyncIOMotorClient = None
    db = None

db_instance = Database()

async def connect_to_mongo():
    """Connect to MongoDB Atlas"""
    try:
        db_instance.client = AsyncIOMotorClient(MONGODB_URL)
        # Test the connection
        await db_instance.client.admin.command('ping')
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
    return db_instance.db