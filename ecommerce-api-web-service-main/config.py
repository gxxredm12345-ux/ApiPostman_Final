import os
from datetime import timedelta
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    db_url = os.getenv("DATABASE_URL", "sqlite:///local.db")

    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = db_url

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
