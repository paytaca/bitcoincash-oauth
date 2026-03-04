"""
Bitcoin Cash OAuth FastAPI - Configuration
Settings management using Pydantic Settings
"""

from functools import lru_cache
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """
    Bitcoin Cash OAuth FastAPI Settings

    All settings can be configured via environment variables
    with the prefix BITCOINCASH_OAUTH_

    Example:
        BITCOINCASH_OAUTH_ACCESS_TOKEN_LIFETIME=3600
        BITCOINCASH_OAUTH_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db
    """

    # Application settings
    APP_NAME: str = Field(default="Bitcoin Cash OAuth", description="Application name")
    DEBUG: bool = Field(default=False, description="Debug mode")

    # Token lifetimes (in seconds)
    ACCESS_TOKEN_LIFETIME: int = Field(
        default=3600,  # 1 hour
        ge=60,  # Minimum 1 minute
        description="Access token lifetime in seconds",
    )
    REFRESH_TOKEN_LIFETIME: int = Field(
        default=604800,  # 7 days
        ge=3600,  # Minimum 1 hour
        description="Refresh token lifetime in seconds",
    )

    # Token settings
    MAX_TOKENS_PER_USER: int = Field(
        default=5, ge=1, description="Maximum number of concurrent tokens per user"
    )
    TOKEN_CLEANUP_DAYS: int = Field(
        default=7, ge=1, description="Days after which to delete expired/revoked tokens"
    )

    # Authentication settings
    MAX_TIMESTAMP_DIFF: int = Field(
        default=300,  # 5 minutes
        ge=30,  # Minimum 30 seconds
        description="Maximum time difference for timestamp validation (replay protection)",
    )
    DEFAULT_SCOPES: List[str] = Field(
        default=["read"], description="Default OAuth scopes for new tokens"
    )

    # Security settings
    REQUIRE_SIGNATURE_FOR_REGISTRATION: bool = Field(
        default=True,
        description="Require signature verification for registration (prevents wallet squatting)",
    )

    # Network settings
    NETWORK: str = Field(
        default="mainnet",
        pattern="^(mainnet|testnet|regtest)$",
        description="Bitcoin Cash network (mainnet, testnet, or regtest)",
    )

    # Database settings
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./bitcoincash_oauth.db",
        description="Database URL (supports PostgreSQL, MySQL, SQLite)",
    )
    DATABASE_POOL_SIZE: int = Field(default=5, ge=1)
    DATABASE_MAX_OVERFLOW: int = Field(default=10, ge=0)

    # Cache/Redis settings (for token blacklist)
    REDIS_URL: Optional[str] = Field(
        default=None,
        description="Redis URL for token blacklist (recommended for production)",
    )
    CACHE_PREFIX: str = Field(default="bitcoincash_oauth")

    # Rate limiting settings
    RATE_LIMIT_TOKEN_ENDPOINT: str = Field(default="5/minute")
    RATE_LIMIT_REFRESH_ENDPOINT: str = Field(default="10/minute")
    RATE_LIMIT_REGISTER_ENDPOINT: str = Field(default="3/minute")

    # Router prefix
    ROUTER_PREFIX: str = Field(default="/auth")

    class Config:
        env_prefix = "BITCOINCASH_OAUTH_"
        case_sensitive = True

    @field_validator("DEFAULT_SCOPES", mode="before")
    @classmethod
    def parse_scopes(cls, v):
        """Parse scopes from string if needed"""
        if isinstance(v, str):
            return [scope.strip() for scope in v.split(",")]
        return v


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance

    Returns:
        Settings instance
    """
    return Settings()


def reload_settings() -> Settings:
    """
    Reload settings (useful for testing)

    Returns:
        New Settings instance
    """
    get_settings.cache_clear()
    return get_settings()
