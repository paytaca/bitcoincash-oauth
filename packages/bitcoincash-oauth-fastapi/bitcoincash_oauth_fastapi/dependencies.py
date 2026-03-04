"""
Bitcoin Cash OAuth FastAPI - Dependencies
FastAPI Depends() functions for authentication and authorization

Usage:
    @app.get("/protected")
    async def protected_endpoint(
        user: BitcoinCashUser = Depends(get_current_user),
        scopes: List[str] = Depends(has_scope(["read", "write"]))
    ):
        return {"user_id": user.user_id}
"""

from typing import Optional, List
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .database import get_db
from .models import BitcoinCashUser, OAuthToken
from .cache import cache_manager
from .exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    RevokedTokenError,
    InsufficientScopeError,
)

# Security scheme
oauth2_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> BitcoinCashUser:
    """
    FastAPI dependency to get the current authenticated user

    Usage:
        @app.get("/me")
        async def get_me(user: BitcoinCashUser = Depends(get_current_user)):
            return {"user_id": user.user_id}

    Raises:
        HTTPException: 401 if not authenticated
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_str = credentials.credentials

    # Check blacklist first
    if await cache_manager.is_blacklisted(token_str):
        raise RevokedTokenError().to_http_exception()

    # Validate token
    token = await OAuthToken.validate_access_token(db, token_str)

    if not token:
        raise InvalidTokenError().to_http_exception()

    return token.user


async def get_current_token(
    credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> OAuthToken:
    """
    FastAPI dependency to get the current OAuth token

    Usage:
        @app.get("/token-info")
        async def token_info(token: OAuthToken = Depends(get_current_token)):
            return {"scopes": token.scopes, "expires_in": token.expires_in}
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_str = credentials.credentials

    # Check blacklist
    if await cache_manager.is_blacklisted(token_str):
        raise RevokedTokenError().to_http_exception()

    # Validate token
    token = await OAuthToken.validate_access_token(db, token_str)

    if not token:
        raise InvalidTokenError().to_http_exception()

    return token


def has_scope(required_scopes: List[str]):
    """
    FastAPI dependency factory to check for required scopes

    Usage:
        @app.post("/write")
        async def write_endpoint(
            _: None = Depends(has_scope(["write"]))
        ):
            pass

        # Multiple scopes (OR logic)
        @app.get("/admin")
        async def admin_endpoint(
            _: None = Depends(has_scope(["admin", "superuser"]))
        ):
            pass

    Args:
        required_scopes: List of required scopes (any one is sufficient)
    """

    async def check_scope(token: OAuthToken = Depends(get_current_token)) -> None:
        user_scopes = set(token.scopes)
        required = set(required_scopes)

        if not user_scopes & required:
            raise InsufficientScopeError(
                required_scopes=list(required)
            ).to_http_exception()

    return check_scope


def has_all_scopes(required_scopes: List[str]):
    """
    FastAPI dependency factory to check for all required scopes (AND logic)

    Usage:
        @app.post("/critical")
        async def critical_endpoint(
            _: None = Depends(has_all_scopes(["read", "write", "admin"]))
        ):
            pass

    Args:
        required_scopes: List of required scopes (all must be present)
    """

    async def check_all_scopes(token: OAuthToken = Depends(get_current_token)) -> None:
        user_scopes = set(token.scopes)
        required = set(required_scopes)

        if not required.issubset(user_scopes):
            raise InsufficientScopeError(
                required_scopes=list(required)
            ).to_http_exception()

    return check_all_scopes


async def get_wallet_hash(user: BitcoinCashUser = Depends(get_current_user)) -> str:
    """
    FastAPI dependency to get the wallet hash (user_id)

    Usage:
        @app.get("/wallet")
        async def get_wallet(wallet_hash: str = Depends(get_wallet_hash)):
            return {"wallet_hash": wallet_hash}
    """
    return user.user_id


async def get_bitcoin_address(user: BitcoinCashUser = Depends(get_current_user)) -> str:
    """
    FastAPI dependency to get the Bitcoin Cash address

    Usage:
        @app.get("/address")
        async def get_address(address: str = Depends(get_bitcoin_address)):
            return {"address": address}
    """
    return user.bitcoin_address


async def get_oauth_scopes(token: OAuthToken = Depends(get_current_token)) -> List[str]:
    """
    FastAPI dependency to get OAuth scopes

    Usage:
        @app.get("/scopes")
        async def get_scopes(scopes: List[str] = Depends(get_oauth_scopes)):
            return {"scopes": scopes}
    """
    return token.scopes


class RequireOwner:
    """
    Dependency class to require resource ownership

    Usage:
        @app.get("/users/{user_id}/data")
        async def get_user_data(
            user_id: str,
            _: None = Depends(RequireOwner("user_id"))
        ):
            pass
    """

    def __init__(self, param_name: str = "user_id"):
        self.param_name = param_name

    async def __call__(
        self, current_user: BitcoinCashUser = Depends(get_current_user), **kwargs
    ) -> None:
        target_id = kwargs.get(self.param_name)

        if target_id and current_user.user_id != target_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only access your own resources",
            )


class RequireOwnerOrReadOnly:
    """
    Dependency class for owner-only writes, public reads

    Usage:
        @app.api_route("/users/{user_id}/profile", methods=["GET", "PUT"])
        async def user_profile(
            user_id: str,
            request: Request,
            _: None = Depends(RequireOwnerOrReadOnly("user_id"))
        ):
            pass
    """

    def __init__(self, param_name: str = "user_id"):
        self.param_name = param_name

    async def __call__(
        self,
        request,
        current_user: BitcoinCashUser = Depends(get_current_user),
        **kwargs,
    ) -> None:
        # Allow read methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return

        # Write methods require ownership
        target_id = kwargs.get(self.param_name)

        if target_id and current_user.user_id != target_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only modify your own resources",
            )
