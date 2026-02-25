"""
Bitcoin Cash OAuth Django - Main module
"""

from .validator import (
    BitcoinCashValidator,
    verify_bitcoin_cash_auth,
    public_key_to_cash_address,
)
from .token_manager import TokenManager, TokenData, token_manager
from .views import (
    BitcoinCashOAuthViews,
    oauth_views,
    register,
    token,
    refresh,
    revoke,
    me,
)
from .drf import (
    IsBitcoinCashAuthenticated,
    HasScope,
    RegisterView,
    TokenView,
    RefreshView,
    RevokeView,
    MeView,
)

__version__ = "1.0.0"

__all__ = [
    # Core
    "BitcoinCashValidator",
    "verify_bitcoin_cash_auth",
    "public_key_to_cash_address",
    "TokenManager",
    "TokenData",
    "token_manager",
    # Django views
    "BitcoinCashOAuthViews",
    "oauth_views",
    "register",
    "token",
    "refresh",
    "revoke",
    "me",
    # DRF
    "IsBitcoinCashAuthenticated",
    "HasScope",
    "RegisterView",
    "TokenView",
    "RefreshView",
    "RevokeView",
    "MeView",
]
