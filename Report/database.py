
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from fastapi import Depends
#from .config import settings  # Assume you have a settings file for DB config

# Define the database URL
#SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASSWORD}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
SQLALCHEMY_DATABASE_URL = f"postgresql://argosuser:Fridaynight1!@192.168.7.178:5432/argosdb"

# Create the database engine
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"options": "-c search_path=argos_firewall"})

# Create a SessionLocal class that will create session instances
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for models
Base = declarative_base()

# Dependency to get the database session for each request
def get_db() -> Session:
    db = SessionLocal()  # Create a new database session
    try:
        yield db  # Yield the session to the caller
    finally:
        db.close()  # Ensure the session is closed after the request