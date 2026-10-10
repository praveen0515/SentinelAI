"""
SentinelAI Configuration Module
Provides centralized configuration management with environment variable support.
"""

import os
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "SentinelAI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, validation_alias="DEBUG")
    ENVIRONMENT: str = Field(default="development", validation_alias="ENVIRONMENT")

    # Server Bindings
    HOST: str = Field(default="0.0.0.0", validation_alias="HOST")
    PORT: int = Field(default=8000, validation_alias="PORT")
    CORS_ORIGINS: List[str] = ["*"]

    # MongoDB Connection
    MONGODB_URI: str = Field(
        default="mongodb://localhost:27017",
        validation_alias="MONGODB_URI"
    )
    MONGODB_DB_NAME: str = Field(
        default="sentinel_ai",
        validation_alias="MONGODB_DB_NAME"
    )

    # ML Model Configuration
    MODEL_DIR: str = Field(default="data", validation_alias="MODEL_DIR")
    MODEL_FILE: str = Field(default="isolation_forest.joblib", validation_alias="MODEL_FILE")
    METADATA_FILE: str = Field(default="model_metadata.json", validation_alias="METADATA_FILE")
    CONTAMINATION_RATE: float = Field(default=0.05, validation_alias="CONTAMINATION_RATE")
    N_ESTIMATORS: int = Field(default=150, validation_alias="N_ESTIMATORS")
    RANDOM_STATE: int = Field(default=42, validation_alias="RANDOM_STATE")

    # Threat Scoring Thresholds
    # IsolationForest decision_function outputs negative values for anomalies
    SCORE_THRESHOLD_LOW: float = -0.05
    SCORE_THRESHOLD_MEDIUM: float = -0.15
    SCORE_THRESHOLD_HIGH: float = -0.25
    SCORE_THRESHOLD_CRITICAL: float = -0.35

    # Streaming and Windowing
    IP_WINDOW_SECONDS: int = 300  # 5 minutes rolling window for IP tracking
    MAX_HISTORICAL_LOGS_QUERY: int = 2000

    @property
    def model_path(self) -> str:
        return os.path.join(self.MODEL_DIR, self.MODEL_FILE)

    @property
    def metadata_path(self) -> str:
        return os.path.join(self.MODEL_DIR, self.METADATA_FILE)

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
