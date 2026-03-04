"""
Bitcoin Cash OAuth FastAPI v2.0

FastAPI package for Bitcoin Cash OAuth authentication with database persistence,
signature-based registration, and comprehensive security features.

Quick Start:
    from fastapi import FastAPI
    from bitcoincash_oauth_fastapi import create_oauth_router, init_oauth

    app = FastAPI()

    # Initialize on startup
    @app.on_event("startup")
    async def startup():
        await init_oauth()

    # Include router
    app.include_router(create_oauth_router())

Configuration (via environment variables):
    BITCOINCASH_OAUTH_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db
    BITCOINCASH_OAUTH_ACCESS_TOKEN_LIFETIME=3600
    BITCOINCASH_OAUTH_REFRESH_TOKEN_LIFETIME=604800
    BITCOINCASH_OAUTH_REDIS_URL=redis://localhost:6379/0
"""

__version__ = "0.2.0"

# Core exports
from .config import Settings, get_settings, reload_settings
from .database import DatabaseManager, db_manager, get_db
from .cache import CacheManager, cache_manager

# Models
from .models import Base, BitcoinCashUser, OAuthToken

# Exceptions
from .exceptions import (
    BitcoinCashAuthError,
    InvalidSignatureError,
    ExpiredTimestampError,
    TokenExpiredError,
    RefreshTokenExpiredError,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidTokenError,
    RevokedTokenError,
    InvalidAddressError,
    AddressMismatchError,
    InsufficientScopeError,
    RateLimitExceededError,
    RegistrationError,
    ConfigurationError,
)

# Validator (existing)
from .validator import (
    BitcoinCashValidator,
    verify_bitcoin_cash_auth,
    public_key_to_cash_address,
)

# Dependencies
from .dependencies import (
    oauth2_scheme,
    get_current_user,
    get_current_token,
    has_scope,
    has_all_scopes,
    get_wallet_hash,
    get_bitcoin_address,
    get_oauth_scopes,
    RequireOwner,
    RequireOwnerOrReadOnly,
)

# Events
from .events import (
    oauth_events,
    emit_token_created,
    emit_token_refreshed,
    emit_token_revoked,
    emit_user_registered,
    emit_user_authenticated,
    emit_authentication_failed,
    emit_registration_failed,
)

# Utilities
from .utils import (
    create_registration_message,
    get_client_ip,
    get_user_agent,
    extract_token_from_request,
    filter_by_owner,
    get_user_token_count,
    cleanup_user_tokens,
    TokenExpiryInfo,
    paginate_query,
    get_pagination_info,
)

# Router
from .router import create_oauth_router

# Legacy (backwards compatibility)
from .token_manager import (
    TokenData,
    TokenManager,
    token_manager,
)


async def init_oauth():
    """
    Initialize the OAuth system

    Call this on application startup:

        @app.on_event("startup")
        async def startup():
            await init_oauth()
    """
    # Initialize database
    await db_manager.init_db()

    # Initialize cache
    await cache_manager.init()

    print(f"[BitcoinCashOAuth] v{__version__} initialized")


async def close_oauth():
    """
    Close OAuth connections

    Call this on application shutdown:

        @app.on_event("shutdown")
        async def shutdown():
            await close_oauth()
    """
    await db_manager.close()
    await cache_manager.close()


# Backwards compatibility
BitcoinCashOAuth = None  # Deprecated, use create_oauth_router instead

__all__ = [
    # Version
    "__version__",
    # Configuration
    "Settings",
    "get_settings",
    "reload_settings",
    # Database
    "DatabaseManager",
    "db_manager",
    "get_db",
    # Cache
    "CacheManager",
    "cache_manager",
    # Models
    "Base",
    "BitcoinCashUser",
    "OAuthToken",
    # Exceptions
    "BitcoinCashAuthError",
    "InvalidSignatureError",
    "ExpiredTimestampError",
    "TokenExpiredError",
    "RefreshTokenExpiredError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "InvalidTokenError",
    "RevokedTokenError",
    "InvalidAddressError",
    "AddressMismatchError",
    "InsufficientScopeError",
    "RateLimitExceededError",
    "RegistrationError",
    "ConfigurationError",
    # Validator
    "BitcoinCashValidator",
    "verify_bitcoin_cash_auth",
    "public_key_to_cash_address",
    # Dependencies
    "oauth2_scheme",
    "get_current_user",
    "get_current_token",
    "has_scope",
    "has_all_scopes",
    "get_wallet_hash",
    "get_bitcoin_address",
    "get_oauth_scopes",
    "RequireOwner",
    "RequireOwnerOrReadOnly",
    # Events
    "oauth_events",
    "emit_token_created",
    "emit_token_refreshed",
    "emit_token_revoked",
    "emit_user_registered",
    "emit_user_authenticated",
    "emit_authentication_failed",
    "emit_registration_failed",
    # Utilities
    "create_registration_message",
    "get_client_ip",
    "get_user_agent",
    "extract_token_from_request",
    "filter_by_owner",
    "get_user_token_count",
    "cleanup_user_tokens",
    "TokenExpiryInfo",
    "paginate_query",
    "get_pagination_info",
    # Router
    "create_oauth_router",
    # Lifecycle
    "init_oauth",
    "close_oauth",
    # Legacy
    "TokenData",
    "TokenManager",
    "token_manager",
]
