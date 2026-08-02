import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelAI SOC Platform"
    API_V1_STR: str = "/api"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "SUPER_SECRET_SECURITY_PHRASE_SENTINEL_AI_2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    
    # Database
    DATABASE_URL: str = "sqlite:///./database/sentinel.db"
    
    # AI Providers
    OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY")
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    OLLAMA_URL: str = "http://localhost:11434"
    AI_PROVIDER: str = "openrouter"  # openrouter, gemini, openai, ollama
    AI_MODEL: Optional[str] = "meta-llama/llama-3.3-70b-instruct:free"  # e.g. meta-llama/llama-3.3-70b-instruct:free or google/gemini-2.0-flash-lite-preview-02-05:free
    
    # Notifications / Email (Mocked by default)
    SMTP_SERVER: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    ALERT_EMAIL: str = "soc-alert@sentinelai.local"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
