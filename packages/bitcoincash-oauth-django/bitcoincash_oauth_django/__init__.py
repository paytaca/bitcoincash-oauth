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
__version__ = "0.2.0"

# These modules don't depend on Django being initialized first
# and can be safely imported at module level
from .validator import (
    BitcoinCashValidator,
    verify_bitcoin_cash_auth,
    public_key_to_cash_address,
)

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

# Default app config for Django
# This is used by Django to find the AppConfig
default_app_config = "bitcoincash_oauth_django.apps.BitcoinCashOAuthConfig"

# Lazy import registry - these modules have Django dependencies
# and will only be imported when their attributes are accessed
_LAZY_MODULES = {
    # Settings (has django.conf imports)
    "get_settings": (".settings", "get_settings"),
    "check_settings": (".settings", "check_settings"),
    # Utilities (has django.http imports)
    "get_wallet_hash": (".utils", "get_wallet_hash"),
    "get_bitcoin_address": (".utils", "get_bitcoin_address"),
    "get_oauth_scopes": (".utils", "get_oauth_scopes"),
    "has_scope": (".utils", "has_scope"),
    "get_current_token": (".utils", "get_current_token"),
    "extract_token_from_request": (".utils", "extract_token_from_request"),
    "create_registration_message": (".utils", "create_registration_message"),
    "filter_by_owner": (".utils", "filter_by_owner"),
    "WalletHashExtractor": (".utils", "WalletHashExtractor"),
    # Authentication (has django.contrib.auth imports)
    "BitcoinCashOAuthBackend": (".authentication", "BitcoinCashOAuthBackend"),
    "BitcoinCashModelBackend": (".authentication", "BitcoinCashModelBackend"),
    # Signals (has django.dispatch imports)
    "token_created": (".signals", "token_created"),
    "token_refreshed": (".signals", "token_refreshed"),
    "token_revoked": (".signals", "token_revoked"),
    "user_registered": (".signals", "user_registered"),
    "user_authenticated": (".signals", "user_authenticated"),
    "authentication_failed": (".signals", "authentication_failed"),
    "registration_failed": (".signals", "registration_failed"),
    # Token manager (legacy)
    "TokenManager": (".token_manager", "TokenManager"),
    "TokenData": (".token_manager", "TokenData"),
    "token_manager": (".token_manager", "token_manager"),
    # Views (has django.http imports)
    "BitcoinCashOAuthViews": (".views", "BitcoinCashOAuthViews"),
    "oauth_views": (".views", "oauth_views"),
    "register": (".views", "register"),
    "token": (".views", "token"),
    "refresh": (".views", "refresh"),
    "revoke": (".views", "revoke"),
    "me": (".views", "me"),
    # DRF Views (has Django/DRF imports)
    "IsBitcoinCashAuthenticated": (".drf_views", "IsBitcoinCashAuthenticated"),
    "HasScope": (".drf_views", "HasScope"),
    "IsOwner": (".drf_views", "IsOwner"),
    "IsOwnerOrReadOnly": (".drf_views", "IsOwnerOrReadOnly"),
    "RegisterView": (".drf_views", "RegisterView"),
    "TokenView": (".drf_views", "TokenView"),
    "RefreshView": (".drf_views", "RefreshView"),
    "RevokeView": (".drf_views", "RevokeView"),
    "MeView": (".drf_views", "MeView"),
    # Permissions (has Django imports)
    "HasAllScopes": (".permissions", "HasAllScopes"),
    "HasReadScope": (".permissions", "HasReadScope"),
    "HasWriteScope": (".permissions", "HasWriteScope"),
    "HasAdminScope": (".permissions", "HasAdminScope"),
    "HasWalletAddress": (".permissions", "HasWalletAddress"),
    "IsStaff": (".permissions", "IsStaff"),
    "IsSuperUser": (".permissions", "IsSuperUser"),
    # Middleware (has Django imports)
    "TokenValidationMiddleware": (".middleware", "TokenValidationMiddleware"),
    "TokenExpiryHeaderMiddleware": (".middleware", "TokenExpiryHeaderMiddleware"),
    "TokenBlacklistMiddleware": (".middleware", "TokenBlacklistMiddleware"),
    # Testing (has Django imports)
    "OAuthTestCase": (".testing", "OAuthTestCase"),
    "MockSignatureVerifier": (".testing", "MockSignatureVerifier"),
}


def __getattr__(name: str):
    """
    Lazy import mechanism for Django-dependent modules.

    This prevents AppRegistryNotReady errors by only importing
    Django-dependent modules when their attributes are actually accessed.
    """
    if name in _LAZY_MODULES:
        module_path, attr_name = _LAZY_MODULES[name]
        # Import the module
        module = __import__(module_path, fromlist=[attr_name])
        # Get the attribute
        return getattr(module, attr_name)

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__():
    """Return all available attributes for introspection."""
    return list(_LAZY_MODULES.keys()) + [
        # Always available
        "__version__",
        "BitcoinCashValidator",
        "verify_bitcoin_cash_auth",
        "public_key_to_cash_address",
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
        # Config
        "default_app_config",
    ]


# Note: Models are NOT exported at module level.
# Import from .models directly or use django.apps.apps.get_model()
# This is necessary to avoid AppRegistryNotReady errors.

__all__ = __dir__()
