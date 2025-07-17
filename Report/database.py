import sys
import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from fastapi import Depends

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Common')))

from Config import Config

config = Config() 
settings = config.GetConfig("PushDB")

# Define the database URL
SQLALCHEMY_DATABASE_URL = f"postgresql://{settings['userID']}:{settings['password']}@{settings['serverIP']}:5432/{settings['database']}"
# SQLALCHEMY_DATABASE_URL = f"postgresql://argosuser:Fridaynight1!@192.168.7.178:5432/argosdb"

# Create the database engine
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"options": "-c search_path=argos_firewall"})
report_engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"options": "-c search_path=compliance"})

# Create a SessionLocal class that will create session instances
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ReportSession = sessionmaker(autocommit=False, autoflush=False, bind=report_engine)

# Create a base class for models
Base = declarative_base()

# Dependency to get the database session for each request
def get_argos_db() -> Session:
    db = SessionLocal()  # Create a new database session
    try:
        yield db  # Yield the session to the caller
    finally:
        db.close()  # Ensure the session is closed after the request

def get_report_db() -> Session:
    db = ReportSession()  # Create a new database session
    try:
        yield db  # Yield the session to the caller
    finally:
        db.close()  # Ensure the session is closed after the request