"""
Bitcoin Cash OAuth FastAPI - Integration module
FastAPI routes and dependencies for Bitcoin Cash OAuth
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from .validator import BitcoinCashValidator, verify_bitcoin_cash_auth
from .token_manager import token_manager, TokenData


# Pydantic models for request/response
class RegisterRequest(BaseModel):
    address: str
    user_id: Optional[str] = None


class RegisterResponse(BaseModel):
    user_id: str
    address: str
    message: str


class TokenRequest(BaseModel):
    user_id: str
    timestamp: int = Field(..., description="Unix timestamp when message was signed")
    domain: str = Field(
        default="oauth", description="Domain for message binding (prevents phishing)"
    )
    public_key: str = Field(..., description="Hex-encoded public key")
    signature: str = Field(..., description="DER-encoded signature in hex")
    scopes: Optional[List[str]] = Field(default=["read"], description="OAuth scopes")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    scopes: List[str]


class RefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    token: str


class UserInfoResponse(BaseModel):
    user_id: str
    address: str
    scopes: List[str]
    expires_at: float


class BitcoinCashOAuth:
    """Main class for integrating Bitcoin Cash OAuth into FastAPI applications"""

    def __init__(
        self,
        router_prefix: str = "/auth",
        token_ttl: int = 3600,
        refresh_token_ttl: int = 2592000,
        max_tokens_per_user: int = 5,
        max_timestamp_diff: int = 300,
    ):
        self.router_prefix = router_prefix
        self.token_manager = token_manager
        self.token_manager.access_token_ttl = token_ttl
        self.token_manager.refresh_token_ttl = refresh_token_ttl
        self.token_manager.max_tokens_per_user = max_tokens_per_user
        self.max_timestamp_diff = max_timestamp_diff
        self.security = HTTPBearer(auto_error=False)

        # Create router
        self.router = self._create_router()

    def _create_router(self) -> APIRouter:
        """Create the API router with all OAuth endpoints"""
        router = APIRouter(prefix=self.router_prefix)

        @router.post("/register", response_model=RegisterResponse)
        async def register_user(request: RegisterRequest):
            """
            Register a new user with a Bitcoin Cash address

            - If user_id is provided, it will be used (must be unique)
            - If not provided, a unique ID will be generated
            """
            # Validate CashAddr format
            is_valid, network = BitcoinCashValidator.validate_cash_address(
                request.address
            )
            if not is_valid:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid Bitcoin Cash CashAddr format. Expected format: bitcoincash:qz...",
                )

            try:
                user_id = self.token_manager.register_user(
                    request.address, request.user_id
                )

                is_new = user_id == request.user_id if request.user_id else True
                message = (
                    "User registered successfully"
                    if is_new
                    else "User already exists, returning existing ID"
                )

                return RegisterResponse(
                    user_id=user_id, address=request.address, message=message
                )

            except ValueError as e:
                raise HTTPException(status_code=409, detail=str(e))

        @router.post("/token", response_model=TokenResponse)
        async def get_token(request: TokenRequest):
            """
            Obtain an OAuth token using Bitcoin Cash signature authentication

            The client must sign the message "{user_id},{timestamp}" with their
            private key and provide the public key and signature.
            """
            # Check if user exists
            if not self.token_manager.user_exists(request.user_id):
                raise HTTPException(
                    status_code=404, detail="User not found. Please register first."
                )

            # Get expected address
            expected_address = self.token_manager.get_user_address(request.user_id)
            if not expected_address:
                raise HTTPException(status_code=500, detail="User address not found")

            # Validate authentication
            is_valid, reason = verify_bitcoin_cash_auth(
                user_id=request.user_id,
                timestamp=request.timestamp,
                public_key=request.public_key,
                signature=request.signature,
                expected_address=expected_address,
                domain=request.domain,
            )

            if not is_valid:
                raise HTTPException(
                    status_code=401, detail=f"Authentication failed: {reason}"
                )

            # Create token pair
            token_data = self.token_manager.create_token_pair(
                user_id=request.user_id, scopes=request.scopes
            )

            return TokenResponse(
                access_token=token_data.access_token,
                token_type=token_data.token_type,
                expires_in=token_data.expires_in,
                refresh_token=token_data.refresh_token,
                scopes=token_data.scopes,
            )

        @router.post("/refresh", response_model=TokenResponse)
        async def refresh_token(request: RefreshRequest):
            """Refresh an access token using a refresh token"""
            new_token = self.token_manager.refresh_access_token(request.refresh_token)

            if not new_token:
                raise HTTPException(
                    status_code=401, detail="Invalid or expired refresh token"
                )

            return TokenResponse(
                access_token=new_token.access_token,
                token_type=new_token.token_type,
                expires_in=new_token.expires_in,
                refresh_token=new_token.refresh_token,
                scopes=new_token.scopes,
            )

        @router.post("/revoke")
        async def revoke_token(request: RevokeRequest):
            """Revoke an access token"""
            success = self.token_manager.revoke_token(request.token)

            if not success:
                raise HTTPException(status_code=404, detail="Token not found")

            return {"message": "Token revoked successfully"}

        @router.get("/me", response_model=UserInfoResponse)
        async def get_current_user_info(
            token_data: TokenData = Depends(self.get_current_user),
        ):
            """Get information about the currently authenticated user"""
            address = self.token_manager.get_user_address(token_data.user_id)

            return UserInfoResponse(
                user_id=token_data.user_id,
                address=address,
                scopes=token_data.scopes,
                expires_at=token_data.expires_at,
            )

        return router

    async def get_current_user(
        self,
        credentials: HTTPAuthorizationCredentials = Depends(),
    ) -> TokenData:
        """Dependency to validate access token and return user info"""
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Authorization header missing",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = credentials.credentials
        token_data = self.token_manager.validate_access_token(token)

        if not token_data:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return token_data

    def get_user_dependency(self):
        """Returns a dependency that can be used to protect routes"""
        return Depends(self.get_current_user)


def create_oauth_router(
    router_prefix: str = "/auth",
    token_ttl: int = 3600,
    refresh_token_ttl: int = 2592000,
    max_tokens_per_user: int = 5,
) -> APIRouter:
    """
    Convenience function to create a pre-configured OAuth router

    Args:
        router_prefix: URL prefix for OAuth endpoints (default: /auth)
        token_ttl: Access token TTL in seconds (default: 3600)
        refresh_token_ttl: Refresh token TTL in seconds (default: 2592000)
        max_tokens_per_user: Maximum tokens per user (default: 5)

    Returns:
        Configured APIRouter with OAuth endpoints

    Example:
        from fastapi import FastAPI
        from bitcoincash_oauth_fastapi import create_oauth_router

        app = FastAPI()
        app.include_router(create_oauth_router())
    """
    oauth = BitcoinCashOAuth(
        router_prefix="",  # No additional prefix since we'll mount at prefix
        token_ttl=token_ttl,
        refresh_token_ttl=refresh_token_ttl,
        max_tokens_per_user=max_tokens_per_user,
    )
    return oauth.router
