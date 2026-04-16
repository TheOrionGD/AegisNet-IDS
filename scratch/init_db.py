import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
from dotenv import load_dotenv

load_dotenv()

def create_database():
    # Use the default 'postgres' database to connect and create the new database
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not found in .env")
        return

    # Extract connection info from URL
    # Format: postgresql://user:password@host:port/dbname
    try:
        base_url = db_url.rsplit('/', 1)[0] + '/postgres'
        print(f"Connecting to {base_url} to create database...")
        
        conn = psycopg2.connect(base_url)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'aegisnet'")
        exists = cur.fetchone()
        
        if not exists:
            cur.execute('CREATE DATABASE aegisnet')
            print("Database 'aegisnet' created successfully.")
        else:
            print("Database 'aegisnet' already exists.")
            
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error creating database: {e}")

if __name__ == "__main__":
    create_database()
