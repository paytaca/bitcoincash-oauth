"""
Bitcoin Cash OAuth Django - Exceptions
Custom exception classes for better error handling
"""


class BitcoinCashAuthError(Exception):
    """Base exception for Bitcoin Cash OAuth errors"""

    def __init__(self, message, code=None, status_code=None):
        super().__init__(message)
        self.message = message
        self.code = code or "auth_error"
        self.status_code = status_code or 400


class InvalidSignatureError(BitcoinCashAuthError):
    """Raised when signature verification fails"""

    def __init__(self, message="Invalid signature"):
        super().__init__(message=message, code="invalid_signature", status_code=401)


class ExpiredTimestampError(BitcoinCashAuthError):
    """Raised when the timestamp is too old"""

    def __init__(self, message="Timestamp expired"):
        super().__init__(message=message, code="expired_timestamp", status_code=401)


class TokenExpiredError(BitcoinCashAuthError):
    """Raised when an access token has expired"""

    def __init__(self, message="Token has expired"):
        super().__init__(message=message, code="token_expired", status_code=401)


class RefreshTokenExpiredError(BitcoinCashAuthError):
    """Raised when a refresh token has expired"""

    def __init__(self, message="Refresh token has expired"):
        super().__init__(message=message, code="refresh_token_expired", status_code=401)


class UserNotFoundError(BitcoinCashAuthError):
    """Raised when a user is not found"""

    def __init__(self, message="User not found"):
        super().__init__(message=message, code="user_not_found", status_code=404)


class UserAlreadyExistsError(BitcoinCashAuthError):
    """Raised when trying to register a user that already exists"""

    def __init__(self, message="User already exists"):
        super().__init__(message=message, code="user_already_exists", status_code=409)


class InvalidTokenError(BitcoinCashAuthError):
    """Raised when a token is invalid"""

    def __init__(self, message="Invalid token"):
        super().__init__(message=message, code="invalid_token", status_code=401)


class RevokedTokenError(BitcoinCashAuthError):
    """Raised when a token has been revoked"""

    def __init__(self, message="Token has been revoked"):
        super().__init__(message=message, code="token_revoked", status_code=401)


class InvalidAddressError(BitcoinCashAuthError):
    """Raised when a Bitcoin Cash address is invalid"""

    def __init__(self, message="Invalid Bitcoin Cash address"):
        super().__init__(message=message, code="invalid_address", status_code=400)


class AddressMismatchError(BitcoinCashAuthError):
    """Raised when the derived address doesn't match the expected address"""

    def __init__(self, message="Address mismatch"):
        super().__init__(message=message, code="address_mismatch", status_code=401)


class InsufficientScopeError(BitcoinCashAuthError):
    """Raised when the user doesn't have the required scope"""

    def __init__(self, message="Insufficient scope", required_scopes=None):
        super().__init__(message=message, code="insufficient_scope", status_code=403)
        self.required_scopes = required_scopes or []


class RateLimitExceededError(BitcoinCashAuthError):
    """Raised when rate limit is exceeded"""

    def __init__(self, message="Rate limit exceeded", retry_after=None):
        super().__init__(message=message, code="rate_limit_exceeded", status_code=429)
        self.retry_after = retry_after


class RegistrationError(BitcoinCashAuthError):
    """Raised when registration fails"""

    def __init__(self, message="Registration failed"):
        super().__init__(message=message, code="registration_failed", status_code=400)


class ConfigurationError(BitcoinCashAuthError):
    """Raised when there's a configuration error"""

    def __init__(self, message="Configuration error"):
        super().__init__(message=message, code="configuration_error", status_code=500)
