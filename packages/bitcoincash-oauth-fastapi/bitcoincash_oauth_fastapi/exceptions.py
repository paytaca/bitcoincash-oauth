"""
Bitcoin Cash OAuth FastAPI - Exceptions
Custom exception classes for better error handling
"""

from fastapi import HTTPException, status


class BitcoinCashAuthError(Exception):
    """Base exception for Bitcoin Cash OAuth errors"""

    def __init__(self, message: str, code: str = None, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code or "auth_error"
        self.status_code = status_code

    def to_http_exception(self) -> HTTPException:
        """Convert to FastAPI HTTPException"""
        return HTTPException(
            status_code=self.status_code,
            detail={"error": self.code, "message": self.message},
        )


class InvalidSignatureError(BitcoinCashAuthError):
    """Raised when signature verification fails"""

    def __init__(self, message: str = "Invalid signature"):
        super().__init__(
            message=message,
            code="invalid_signature",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class ExpiredTimestampError(BitcoinCashAuthError):
    """Raised when the timestamp is too old"""

    def __init__(self, message: str = "Timestamp expired"):
        super().__init__(
            message=message,
            code="expired_timestamp",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class TokenExpiredError(BitcoinCashAuthError):
    """Raised when an access token has expired"""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(
            message=message,
            code="token_expired",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class RefreshTokenExpiredError(BitcoinCashAuthError):
    """Raised when a refresh token has expired"""

    def __init__(self, message: str = "Refresh token has expired"):
        super().__init__(
            message=message,
            code="refresh_token_expired",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class UserNotFoundError(BitcoinCashAuthError):
    """Raised when a user is not found"""

    def __init__(self, message: str = "User not found"):
        super().__init__(
            message=message,
            code="user_not_found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class UserAlreadyExistsError(BitcoinCashAuthError):
    """Raised when trying to register a user that already exists"""

    def __init__(self, message: str = "User already exists"):
        super().__init__(
            message=message,
            code="user_already_exists",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidTokenError(BitcoinCashAuthError):
    """Raised when a token is invalid"""

    def __init__(self, message: str = "Invalid token"):
        super().__init__(
            message=message,
            code="invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class RevokedTokenError(BitcoinCashAuthError):
    """Raised when a token has been revoked"""

    def __init__(self, message: str = "Token has been revoked"):
        super().__init__(
            message=message,
            code="token_revoked",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class InvalidAddressError(BitcoinCashAuthError):
    """Raised when a Bitcoin Cash address is invalid"""

    def __init__(self, message: str = "Invalid Bitcoin Cash address"):
        super().__init__(
            message=message,
            code="invalid_address",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class AddressMismatchError(BitcoinCashAuthError):
    """Raised when the derived address doesn't match the expected address"""

    def __init__(self, message: str = "Address mismatch"):
        super().__init__(
            message=message,
            code="address_mismatch",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class InsufficientScopeError(BitcoinCashAuthError):
    """Raised when the user doesn't have the required scope"""

    def __init__(
        self, message: str = "Insufficient scope", required_scopes: list = None
    ):
        super().__init__(
            message=message,
            code="insufficient_scope",
            status_code=status.HTTP_403_FORBIDDEN,
        )
        self.required_scopes = required_scopes or []


class RateLimitExceededError(BitcoinCashAuthError):
    """Raised when rate limit is exceeded"""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = None):
        super().__init__(
            message=message,
            code="rate_limit_exceeded",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
        self.retry_after = retry_after


class RegistrationError(BitcoinCashAuthError):
    """Raised when registration fails"""

    def __init__(self, message: str = "Registration failed"):
        super().__init__(
            message=message,
            code="registration_failed",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConfigurationError(BitcoinCashAuthError):
    """Raised when there's a configuration error"""

    def __init__(self, message: str = "Configuration error"):
        super().__init__(
            message=message,
            code="configuration_error",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
