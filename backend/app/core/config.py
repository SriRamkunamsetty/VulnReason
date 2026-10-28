import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    PROJECT_NAME: str = "VulnReason"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./vulnreason.db"
    SYNC_DATABASE_URL: Optional[str] = "sqlite:///./vulnreason.db"
    
    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security & JWT
    SECRET_KEY: str = "vulnreason-super-secret-key-change-in-production-min32chars!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]
    
    # External APIs
    NVD_API_KEY: Optional[str] = None
    CISA_KEV_FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    OSV_API_URL: str = "https://api.osv.dev/v1"
    
    # AI / LLM Configuration
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    MOCK_LLM_MODE: bool = True

settings = Settings()
