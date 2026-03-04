"""
Bitcoin Cash OAuth Django - Middleware
Automatic token validation and cleanup middleware
"""

from django.utils import timezone
from django.http import JsonResponse
from django.core.cache import cache

from .settings import get_settings


def _get_token_model():
    """Get the token model class lazily"""
    return get_settings().get_token_model()


class TokenValidationMiddleware:
    """
    Middleware that automatically validates tokens and handles expiration

    Features:
    - Validates tokens on each request
    - Automatic cleanup of expired tokens (rate-limited)
    - Adds token info to request

    Usage:
        MIDDLEWARE = [
            ...
            'bitcoincash_oauth_django.middleware.TokenValidationMiddleware',
        ]

    Note: This should be placed AFTER AuthenticationMiddleware
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Cache key for tracking cleanup runs
        self.cleanup_cache_key = "bitcoincash_oauth_last_cleanup"

    def __call__(self, request):
        # Check if user has an OAuth token
        if hasattr(request, "user") and request.user.is_authenticated:
            # Try to get token from cache or validate
            token = self._get_valid_token(request)

            if token:
                # Check if token is about to expire (optional warning)
                self._check_token_expiry(request, token)

                # Attach token to request
                request.oauth_token = token
                request.oauth_scopes = token.scopes
            else:
                # Token is invalid/expired - could optionally log out user
                pass

        # Periodic cleanup (run once per hour max)
        self._periodic_cleanup()

        response = self.get_response(request)
        return response

    def _get_valid_token(self, request):
        """Get valid token for the request"""
        # Check if we already have token_data from auth backend
        if hasattr(request, "token_data") and isinstance(
            request.token_data, OAuthToken
        ):
            return request.token_data

        # Extract token from header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None

        token_str = auth_header[7:]

        # Check cache first
        cache_key = f"bitcoincash_token_{token_str[:32]}"
        cached_token = cache.get(cache_key)

        if cached_token:
            # Verify it's still valid (not expired since cache)
            if cached_token.expires_at > timezone.now() and not cached_token.is_revoked:
                return cached_token

        # Validate from database
        token = _get_token_model().validate_access_token(token_str)

        if token:
            # Cache valid token for 5 minutes
            cache.set(cache_key, token, 300)

        return token

    def _check_token_expiry(self, request, token):
        """Check if token is about to expire and add warning header"""
        # If token expires in less than 5 minutes, add warning header
        time_to_expiry = token.expires_at - timezone.now()

        if time_to_expiry.total_seconds() < 300:  # 5 minutes
            request.token_about_to_expire = True
            request.token_expires_in_seconds = int(time_to_expiry.total_seconds())

    def _periodic_cleanup(self):
        """Run cleanup periodically (once per hour)"""
        last_cleanup = cache.get(self.cleanup_cache_key)

        if last_cleanup is None:
            # Run cleanup
            try:
                deleted = _get_token_model().cleanup_expired_tokens()
                if deleted > 0:
                    print(f"[BitcoinCashOAuth] Cleaned up {deleted} expired tokens")
            except Exception as e:
                print(f"[BitcoinCashOAuth] Cleanup error: {e}")

            # Set cache to prevent frequent runs (1 hour)
            cache.set(self.cleanup_cache_key, timezone.now(), 3600)


class TokenExpiryHeaderMiddleware:
    """
    Middleware that adds token expiry information to responses

    Adds headers:
    - X-Token-Expires-In: Seconds until token expires
    - X-Token-About-To-Expire: "true" if expires in < 5 minutes

    Usage:
        MIDDLEWARE = [
            ...
            'bitcoincash_oauth_django.middleware.TokenExpiryHeaderMiddleware',
        ]
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Add expiry info if available
        if hasattr(request, "oauth_token") and request.oauth_token:
            token = request.oauth_token
            expires_in = int((token.expires_at - timezone.now()).total_seconds())

            if expires_in > 0:
                response["X-Token-Expires-In"] = str(expires_in)

                if expires_in < 300:  # 5 minutes
                    response["X-Token-About-To-Expire"] = "true"

        return response


class TokenBlacklistMiddleware:
    """
    Middleware that checks revoked tokens using a blacklist

    This provides an additional layer of security by maintaining
    a blacklist of revoked tokens in cache for faster lookups.

    Usage:
        MIDDLEWARE = [
            ...
            'bitcoincash_oauth_django.middleware.TokenBlacklistMiddleware',
        ]
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.blacklist_prefix = "bitcoincash_token_blacklist_"

    def __call__(self, request):
        # Check if token is blacklisted
        auth_header = request.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:]
            blacklist_key = f"{self.blacklist_prefix}{token_str[:32]}"

            if cache.get(blacklist_key):
                # Token is blacklisted
                return JsonResponse({"error": "Token has been revoked"}, status=401)

        response = self.get_response(request)
        return response

    @staticmethod
    def blacklist_token(token_str, expiry_seconds=None):
        """Add a token to the blacklist"""
        if expiry_seconds is None:
            # Default to 1 hour
            expiry_seconds = 3600

        blacklist_key = f"bitcoincash_token_blacklist_{token_str[:32]}"
        cache.set(blacklist_key, True, expiry_seconds)
