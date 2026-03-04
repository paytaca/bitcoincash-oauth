"""
Bitcoin Cash OAuth FastAPI - Router
FastAPI router with database persistence and signature-based registration
"""

from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .config import get_settings
from .database import get_db
from .models import BitcoinCashUser, OAuthToken
from .cache import cache_manager
from .exceptions import (
    InvalidAddressError,
    UserAlreadyExistsError,
    UserNotFoundError,
    InvalidSignatureError,
    InvalidTokenError,
    RegistrationError,
)
from .validator import BitcoinCashValidator, verify_bitcoin_cash_auth
from .events import (
    emit_token_created,
    emit_token_refreshed,
    emit_token_revoked,
    emit_user_registered,
    emit_user_authenticated,
    emit_authentication_failed,
    emit_registration_failed,
)
from .utils import get_client_ip, get_user_agent, create_registration_message


# Security scheme
security = HTTPBearer(auto_error=False)


# Pydantic Models


class RegisterRequest(BaseModel):
    """Request model for user registration"""

    address: str = Field(..., description="Bitcoin Cash CashAddr address")
    user_id: Optional[str] = Field(
        None, description="Optional user-provided ID (wallet hash)"
    )
    # Optional signature fields for secure registration
    timestamp: Optional[int] = Field(None, description="Unix timestamp for signature")
    domain: str = Field(default="oauth", description="Domain for message binding")
    public_key: Optional[str] = Field(None, description="Hex-encoded public key")
    signature: Optional[str] = Field(None, description="DER-encoded signature")


class RegisterResponse(BaseModel):
    """Response model for registration"""

    user_id: str
    address: str
    message: str
    signature_required: bool = Field(
        False, description="Whether signature verification is required"
    )


class TokenRequest(BaseModel):
    """Request model for token issuance"""

    user_id: str = Field(..., description="User ID (wallet hash)")
    timestamp: int = Field(..., description="Unix timestamp")
    domain: str = Field(default="oauth", description="Domain for message binding")
    public_key: str = Field(..., description="Hex-encoded public key")
    signature: str = Field(..., description="DER-encoded signature")
    scopes: List[str] = Field(default=["read"], description="Requested OAuth scopes")


class TokenResponse(BaseModel):
    """Response model for token - standardized format"""

    access_token: str
    token_type: str = Field(default="Bearer")
    expires_in: int
    refresh_token: str
    scopes: List[str]
    user_id: str


class RefreshRequest(BaseModel):
    """Request model for token refresh"""

    refresh_token: str


class RevokeRequest(BaseModel):
    """Request model for token revocation"""

    token: str


class RevokeResponse(BaseModel):
    """Response model for revocation"""

    message: str
    user_id: str
    revoked_at: str


class UserInfoResponse(BaseModel):
    """Response model for user info"""

    user_id: str
    address: str
    scopes: List[str]
    expires_at: float


# Router factory function


def create_oauth_router(
    prefix: str = "/auth", tags: List[str] = ["OAuth"]
) -> APIRouter:
    """
    Create FastAPI router with OAuth endpoints

    Args:
        prefix: URL prefix for routes (default: /auth)
        tags: OpenAPI tags

    Returns:
        APIRouter instance

    Usage:
        from fastapi import FastAPI
        from bitcoincash_oauth_fastapi import create_oauth_router

        app = FastAPI()
        app.include_router(create_oauth_router())
    """
    router = APIRouter(prefix=prefix, tags=tags)

    @router.post(
        "/register",
        response_model=RegisterResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Register a new user",
        description="Register a new user with a Bitcoin Cash address. If signature verification is enabled, proof of wallet ownership is required.",
    )
    async def register(
        request: Request, data: RegisterRequest, db: AsyncSession = Depends(get_db)
    ):
        """Register a new user with optional signature verification"""
        settings = get_settings()

        # Validate address format
        is_valid, network = BitcoinCashValidator.validate_cash_address(data.address)
        if not is_valid:
            raise InvalidAddressError().to_http_exception()

        # Check if signature verification is required
        if settings.REQUIRE_SIGNATURE_FOR_REGISTRATION:
            if not all([data.timestamp, data.public_key, data.signature]):
                return RegisterResponse(
                    user_id="",
                    address=data.address,
                    message="Signature verification required",
                    signature_required=True,
                )

            # Verify signature
            user_id_for_sig = data.user_id or data.address
            is_valid_sig, reason = verify_bitcoin_cash_auth(
                user_id=user_id_for_sig,
                timestamp=data.timestamp,
                public_key=data.public_key,
                signature=data.signature,
                expected_address=data.address,
                domain=data.domain,
            )

            if not is_valid_sig:
                await emit_authentication_failed(
                    user_id=data.user_id,
                    reason=f"Registration signature failed: {reason}",
                    request=request,
                )
                raise InvalidSignatureError(
                    f"Signature verification failed: {reason}"
                ).to_http_exception()

        # Check if user already exists by address
        result = await db.execute(
            select(BitcoinCashUser).where(
                BitcoinCashUser.bitcoin_address == data.address
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            return RegisterResponse(
                user_id=existing.user_id,
                address=data.address,
                message="User already exists, returning existing ID",
                signature_required=False,
            )

        # Check if user_id is already taken
        if data.user_id:
            result = await db.execute(
                select(BitcoinCashUser).where(BitcoinCashUser.user_id == data.user_id)
            )
            if result.scalar_one_or_none():
                await emit_registration_failed(
                    address=data.address,
                    reason=f"User ID already exists: {data.user_id}",
                    request=request,
                )
                raise UserAlreadyExistsError().to_http_exception()

        try:
            # Create new user
            user = BitcoinCashUser(
                user_id=data.user_id or data.address,
                bitcoin_address=data.address,
                public_key=data.public_key or "",
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

            await emit_user_registered(user=user, request=request)

            return RegisterResponse(
                user_id=user.user_id,
                address=data.address,
                message="User registered successfully",
                signature_required=False,
            )

        except Exception as e:
            await emit_registration_failed(
                address=data.address, reason=str(e), request=request
            )
            raise RegistrationError(str(e)).to_http_exception()

    @router.post(
        "/token",
        response_model=TokenResponse,
        summary="Obtain OAuth token",
        description="Authenticate using Bitcoin Cash signature and obtain access/refresh tokens",
    )
    async def token(
        request: Request, data: TokenRequest, db: AsyncSession = Depends(get_db)
    ):
        """Obtain an OAuth token using Bitcoin Cash signature authentication"""

        # Check if user exists
        result = await db.execute(
            select(BitcoinCashUser).where(BitcoinCashUser.user_id == data.user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            await emit_authentication_failed(
                user_id=data.user_id, reason="User not found", request=request
            )
            raise UserNotFoundError().to_http_exception()

        # Validate authentication
        is_valid, reason = verify_bitcoin_cash_auth(
            user_id=data.user_id,
            timestamp=data.timestamp,
            public_key=data.public_key,
            signature=data.signature,
            expected_address=user.bitcoin_address,
            domain=data.domain,
        )

        if not is_valid:
            await emit_authentication_failed(
                user_id=data.user_id, reason=reason, request=request
            )
            raise InvalidSignatureError(
                f"Authentication failed: {reason}"
            ).to_http_exception()

        # Update user's public key if provided
        if data.public_key and not user.public_key:
            user.public_key = data.public_key
            await db.commit()

        # Update last activity
        user.updated_at = datetime.now(timezone.utc)
        await db.commit()

        # Create token
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)

        oauth_token = await OAuthToken.create_token_pair(
            db=db,
            user=user,
            scopes=data.scopes,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Emit events
        await emit_token_created(user=user, token=oauth_token, request=request)
        await emit_user_authenticated(user=user, token=oauth_token, request=request)

        return TokenResponse(
            access_token=oauth_token.access_token,
            token_type=oauth_token.token_type,
            expires_in=oauth_token.expires_in,
            refresh_token=oauth_token.refresh_token,
            scopes=oauth_token.scopes,
            user_id=user.user_id,
        )

    @router.post(
        "/refresh",
        response_model=TokenResponse,
        summary="Refresh access token",
        description="Refresh an access token using a refresh token (rotation enabled)",
    )
    async def refresh(
        request: Request, data: RefreshRequest, db: AsyncSession = Depends(get_db)
    ):
        """Refresh an access token using a refresh token"""

        # Validate refresh token
        old_token = await OAuthToken.validate_refresh_token(db, data.refresh_token)

        if not old_token:
            raise InvalidTokenError(
                "Invalid or expired refresh token"
            ).to_http_exception()

        user = old_token.user
        scopes = old_token.scopes

        # Revoke old token
        await old_token.revoke(db)

        # Add to blacklist for immediate effect
        await cache_manager.blacklist_token(
            old_token.access_token, old_token.expires_in
        )
        await cache_manager.blacklist_token(
            old_token.refresh_token,
            old_token.expires_in * 7,  # Refresh tokens live longer
        )

        # Create new token pair (rotation)
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)

        new_token = await OAuthToken.create_token_pair(
            db=db,
            user=user,
            scopes=scopes,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await emit_token_refreshed(
            user=user, old_token=old_token, new_token=new_token, request=request
        )

        return TokenResponse(
            access_token=new_token.access_token,
            token_type=new_token.token_type,
            expires_in=new_token.expires_in,
            refresh_token=new_token.refresh_token,
            scopes=new_token.scopes,
            user_id=user.user_id,
        )

    @router.post(
        "/revoke",
        response_model=RevokeResponse,
        summary="Revoke token",
        description="Revoke an access token (blacklisted immediately)",
    )
    async def revoke(
        request: Request, data: RevokeRequest, db: AsyncSession = Depends(get_db)
    ):
        """Revoke an access token"""

        # Find token
        result = await db.execute(
            select(OAuthToken).where(OAuthToken.access_token == data.token)
        )
        oauth_token = result.scalar_one_or_none()

        if not oauth_token:
            raise InvalidTokenError("Token not found").to_http_exception()

        user = oauth_token.user

        # Calculate blacklist duration
        expires_in = oauth_token.expires_in
        blacklist_duration = max(expires_in, 3600)  # Min 1 hour

        # Revoke in database
        await oauth_token.revoke(db)

        # Add to blacklist
        await cache_manager.blacklist_token(data.token, blacklist_duration)
        if oauth_token.refresh_token:
            await cache_manager.blacklist_token(
                oauth_token.refresh_token, blacklist_duration * 7
            )

        await emit_token_revoked(user=user, token=oauth_token, request=request)

        return RevokeResponse(
            message="Token revoked successfully",
            user_id=user.user_id,
            revoked_at=datetime.now(timezone.utc).isoformat(),
        )

    @router.get(
        "/me",
        response_model=UserInfoResponse,
        summary="Get current user info",
        description="Get information about the currently authenticated user",
    )
    async def me(request: Request, db: AsyncSession = Depends(get_db)):
        """Get current user information"""
        from .dependencies import get_current_token

        token = await get_current_token(request, db)
        user = token.user

        return UserInfoResponse(
            user_id=user.user_id,
            address=user.bitcoin_address,
            scopes=token.scopes,
            expires_at=token.expires_at.timestamp(),
        )

    return router
