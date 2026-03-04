"""
Bitcoin Cash OAuth Django - Utilities
Helper functions for common operations
"""

from django.http import HttpRequest
from .models import OAuthToken, BitcoinCashUser
from .settings import get_settings


def get_wallet_hash(request):
    """
    Get the wallet hash (user_id) from an authenticated request

    Args:
        request: Django request object

    Returns:
        str: The wallet hash, or None if not authenticated

    Usage:
        wallet_hash = get_wallet_hash(request)
        if wallet_hash:
            # User is authenticated
            pass
    """
    if not hasattr(request, "user") or not request.user.is_authenticated:
        return None

    # Check if it's a BitcoinCashUser
    if isinstance(request.user, BitcoinCashUser):
        return request.user.user_id

    # Check for oauth_scopes attribute (set by our auth backend)
    if hasattr(request.user, "oauth_scopes"):
        return request.user.user_id

    return None


def get_bitcoin_address(request):
    """
    Get the Bitcoin Cash address from an authenticated request

    Args:
        request: Django request object

    Returns:
        str: The Bitcoin Cash address, or None if not authenticated
    """
    if not hasattr(request, "user") or not request.user.is_authenticated:
        return None

    if isinstance(request.user, BitcoinCashUser):
        return request.user.bitcoin_address

    # Try to get from user model
    if hasattr(request.user, "bitcoin_address"):
        return request.user.bitcoin_address

    return None


def get_oauth_scopes(request):
    """
    Get the OAuth scopes from an authenticated request

    Args:
        request: Django request object

    Returns:
        list: List of scopes, or empty list if not authenticated
    """
    if not hasattr(request, "user") or not request.user.is_authenticated:
        return []

    # Check for oauth_scopes attribute (set by auth backend or DRF permission)
    if hasattr(request.user, "oauth_scopes"):
        return request.user.oauth_scopes

    if hasattr(request, "oauth_scopes"):
        return request.oauth_scopes

    if hasattr(request, "token_data"):
        return request.token_data.scopes

    return []


def has_scope(request, scope):
    """
    Check if the authenticated user has a specific scope

    Args:
        request: Django request object
        scope: The scope to check for

    Returns:
        bool: True if user has the scope

    Usage:
        if has_scope(request, 'write'):
            # User has write permission
            pass
    """
    scopes = get_oauth_scopes(request)
    return scope in scopes


def get_current_token(request):
    """
    Get the current OAuth token from the request

    Args:
        request: Django request object

    Returns:
        OAuthToken: The token object, or None
    """
    if not hasattr(request, "user") or not request.user.is_authenticated:
        return None

    if hasattr(request.user, "oauth_token"):
        return request.user.oauth_token

    if hasattr(request, "token_data") and isinstance(request.token_data, OAuthToken):
        return request.token_data

    return None


def extract_token_from_request(request):
    """
    Extract the Bearer token from the Authorization header

    Args:
        request: Django request object

    Returns:
        str: The token string, or None
    """
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer "

    return None


def create_registration_message(user_id, timestamp, domain="oauth"):
    """
    Create a registration message to be signed by the client

    This ensures only the wallet owner can register

    Args:
        user_id: The wallet hash
        timestamp: Unix timestamp
        domain: Domain for message binding

    Returns:
        str: The message to sign

    Usage:
        message = create_registration_message(wallet_hash, int(time.time()), 'myapp.com')
        signature = sign_with_wallet(message)  # Client-side
    """
    return f"bitcoincash-oauth|{domain}|{user_id}|{timestamp}|register"


def filter_by_owner(queryset, request, field_name="user_id"):
    """
    Filter a queryset by the authenticated user's wallet hash

    Args:
        queryset: Django queryset to filter
        request: Django request object
        field_name: The field name to filter on (default: 'user_id')

    Returns:
        QuerySet: Filtered queryset

    Usage:
        def get_queryset(self):
            return filter_by_owner(Transaction.objects.all(), self.request)
    """
    wallet_hash = get_wallet_hash(request)

    if wallet_hash is None:
        return queryset.none()

    return queryset.filter(**{field_name: wallet_hash})


class WalletHashExtractor:
    """
    Middleware or mixin to automatically extract wallet hash to request

    Usage as Middleware:
        MIDDLEWARE = [
            ...
            'bitcoincash_oauth_django.utils.WalletHashExtractor',
        ]

    Usage as Mixin:
        class MyView(WalletHashExtractor, APIView):
            def get(self, request):
                wallet_hash = request.wallet_hash  # Already set
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        # Extract wallet hash and attach to request
        request.wallet_hash = get_wallet_hash(request)
        request.bitcoin_address = get_bitcoin_address(request)
        request.oauth_scopes = get_oauth_scopes(request)

        response = self.get_response(request)
        return response
