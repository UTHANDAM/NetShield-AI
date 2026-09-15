from pydantic_settings import BaseSettings
from pydantic import field_validator
from pathlib import Path
import os

# Resolve project root dynamically
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # backend/


class Settings(BaseSettings):
    APP_NAME: str = "NetShield AI"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    @field_validator("DEBUG", mode="before")
    @classmethod
    def normalise_debug(cls, value):
        # Some hosts export DEBUG as a log level (for example, WARN). Treat
        # only explicit development values as true rather than failing startup.
        if isinstance(value, str) and value.lower() not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
            return False
        return value

    # SQLite (zero-setup, no Docker needed)
    DATABASE_PATH: str = str(_PROJECT_ROOT / "netshield.db")
    DATABASE_URL_OVERRIDE: str | None = None
    # Include the production Vercel UI by default. Hosts can still override
    # this value with CORS_ORIGINS in their environment configuration.
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000,https://net-shield-ai-one.vercel.app"
    WEBHOOK_ALLOWLIST: str = ""

    @property
    def DATABASE_URL(self) -> str:
        if self.DATABASE_URL_OVERRIDE:
            return self.DATABASE_URL_OVERRIDE.replace("postgres://", "postgresql+asyncpg://", 1).replace("postgresql://", "postgresql+asyncpg://", 1)
        return f"sqlite+aiosqlite:///{self.DATABASE_PATH}"

    @property
    def cors_origins_list(self) -> list[str]:
        return [item.strip() for item in self.CORS_ORIGINS.split(",") if item.strip()]

    # JWT
    JWT_SECRET: str = "netshield-jwt-secret-key-2024-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440  # 24 hours

    # Dataset paths (relative to project root's parent = "netshield ai" folder)
    _NETSHIELD_ROOT: str = str(_PROJECT_ROOT)

    @property
    def CICIDS_PATH(self) -> str:
        return os.path.join(self._NETSHIELD_ROOT, "DATASET", "CICIDS2017")

    @property
    def UNSW_PATH(self) -> str:
        return os.path.join(self._NETSHIELD_ROOT, "DATASET", "UNSW-NB15 datasets")

    # ML model directory
    @property
    def ML_MODELS_DIR(self) -> str:
        backend_models = _PROJECT_ROOT / "backend" / "app" / "ml" / "models"
        if backend_models.exists():
            return str(backend_models)
        app_models = _PROJECT_ROOT / "app" / "ml" / "models"
        if app_models.exists():
            return str(app_models)
        # Fallback to backend/app/ml/models
        backend_models.mkdir(parents=True, exist_ok=True)
        return str(backend_models)

    # Reports output directory
    @property
    def REPORTS_DIR(self) -> str:
        d = str(_PROJECT_ROOT / "reports")
        os.makedirs(d, exist_ok=True)
        return d

    class Config:
        env_file = ".env"


settings = Settings()
