"""
Bitcoin Cash OAuth Django - Main module

A Django package for Bitcoin Cash OAuth authentication with database persistence,
Django auth integration, and comprehensive DRF support.

Version 2.0.0 - Major release with database support and signature-based registration

Quick Start:
    1. Add 'bitcoincash_oauth_django' to INSTALLED_APPS
    2. Run migrations: python manage.py migrate
    3. Add to urls.py: path('auth/', include('bitcoincash_oauth_django.urls'))
    4. Configure settings in settings.py:

       BITCOINCASH_OAUTH = {
           'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
           'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
           'REQUIRE_SIGNATURE_FOR_REGISTRATION': True,  # Security: verify ownership
       }

    5. Add authentication backend:

       AUTHENTICATION_BACKENDS = [
           'bitcoincash_oauth_django.authentication.BitcoinCashOAuthBackend',
           'django.contrib.auth.backends.ModelBackend',
       ]

Example Usage:
    # views.py
    from bitcoincash_oauth_django.permissions import IsOwner, HasScope
    from bitcoincash_oauth_django.utils import get_wallet_hash

    class MyView(APIView):
        permission_classes = [IsBitcoinCashAuthenticated, IsOwner]

        def get(self, request):
            wallet_hash = request.user.user_id  # or get_wallet_hash(request)
            return Response({"wallet_hash": wallet_hash})
"""

# Version
__version__ = "2.0.0"

# Core validator
from .validator import (
    BitcoinCashValidator,
    verify_bitcoin_cash_auth,
    public_key_to_cash_address,
)

# Models
from .models import (
    BitcoinCashUser,
    OAuthToken,
)

# Settings
from .settings import (
    get_settings,
    check_settings,
)

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

# Utilities
from .utils import (
    get_wallet_hash,
    get_bitcoin_address,
    get_oauth_scopes,
    has_scope,
    get_current_token,
    extract_token_from_request,
    create_registration_message,
    filter_by_owner,
    WalletHashExtractor,
)

# Authentication
from .authentication import (
    BitcoinCashOAuthBackend,
    BitcoinCashModelBackend,
)

# Signals
from .signals import (
    token_created,
    token_refreshed,
    token_revoked,
    user_registered,
    user_authenticated,
    authentication_failed,
    registration_failed,
)

# Legacy token manager (for backwards compatibility)
from .token_manager import (
    TokenManager,
    TokenData,
    token_manager,
)

# Views (legacy - use drf_views for new implementations)
from .views import (
    BitcoinCashOAuthViews,
    oauth_views,
    register,
    token,
    refresh,
    revoke,
    me,
)

# DRF Integration (new views with database support)
from .drf_views import (
    IsBitcoinCashAuthenticated,
    HasScope,
    IsOwner,
    IsOwnerOrReadOnly,
    RegisterView,
    TokenView,
    RefreshView,
    RevokeView,
    MeView,
)

# Permissions
from .permissions import (
    HasAllScopes,
    HasReadScope,
    HasWriteScope,
    HasAdminScope,
    HasWalletAddress,
    IsStaff,
    IsSuperUser,
)

# Default app config for Django
default_app_config = "bitcoincash_oauth_django.apps.BitcoinCashOAuthConfig"

__all__ = [
    # Version
    "__version__",
    # Core
    "BitcoinCashValidator",
    "verify_bitcoin_cash_auth",
    "public_key_to_cash_address",
    # Models
    "BitcoinCashUser",
    "OAuthToken",
    # Settings
    "get_settings",
    "check_settings",
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
    # Utilities
    "get_wallet_hash",
    "get_bitcoin_address",
    "get_oauth_scopes",
    "has_scope",
    "get_current_token",
    "extract_token_from_request",
    "create_registration_message",
    "filter_by_owner",
    "WalletHashExtractor",
    # Authentication
    "BitcoinCashOAuthBackend",
    "BitcoinCashModelBackend",
    # Signals
    "token_created",
    "token_refreshed",
    "token_revoked",
    "user_registered",
    "user_authenticated",
    "authentication_failed",
    "registration_failed",
    # Legacy
    "TokenManager",
    "TokenData",
    "token_manager",
    # Views
    "BitcoinCashOAuthViews",
    "oauth_views",
    "register",
    "token",
    "refresh",
    "revoke",
    "me",
    # DRF Views (v2.0)
    "RegisterView",
    "TokenView",
    "RefreshView",
    "RevokeView",
    "MeView",
    # Permissions
    "IsBitcoinCashAuthenticated",
    "HasScope",
    "HasAllScopes",
    "HasReadScope",
    "HasWriteScope",
    "HasAdminScope",
    "IsOwner",
    "IsOwnerOrReadOnly",
    "HasWalletAddress",
    "IsStaff",
    "IsSuperUser",
]
