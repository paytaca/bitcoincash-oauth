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

    # Custom model paths (to avoid conflicts with existing models)
    # Format: "module.path.ModelClass"
    USER_MODEL: Optional[str] = Field(
        default=None,
        description="Custom user model path (e.g., 'myapp.models.MyBitcoinCashUser')",
    )
    TOKEN_MODEL: Optional[str] = Field(
        default=None,
        description="Custom token model path (e.g., 'myapp.models.MyOAuthToken')",
    )

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


# Model registry for swappable models
_model_registry = {}


def register_model(name: str, model_class):
    """
    Register a custom model class

    Args:
        name: Model name ('user' or 'token')
        model_class: The model class to register
    """
    _model_registry[name] = model_class


def get_user_model():
    """
    Get the user model class

    Returns:
        The user model class (either custom or default BitcoinCashUser)
    """
    from .models import BitcoinCashUser

    settings = get_settings()

    if "user" in _model_registry:
        return _model_registry["user"]

    if settings.USER_MODEL:
        # Dynamically import custom model
        module_path, class_name = settings.USER_MODEL.rsplit(".", 1)
        module = __import__(module_path, fromlist=[class_name])
        return getattr(module, class_name)

    return BitcoinCashUser


def get_token_model():
    """
    Get the token model class

    Returns:
        The token model class (either custom or default OAuthToken)
    """
    from .models import OAuthToken

    settings = get_settings()

    if "token" in _model_registry:
        return _model_registry["token"]

    if settings.TOKEN_MODEL:
        # Dynamically import custom model
        module_path, class_name = settings.TOKEN_MODEL.rsplit(".", 1)
        module = __import__(module_path, fromlist=[class_name])
        return getattr(module, class_name)

    return OAuthToken


def get_model_registry():
    """
    Get the model registry dictionary

    Returns:
        Dict containing registered models
    """
    return _model_registry
