"""
FastAPI server for Bitcoin Cash OAuth
"""

import time
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from validator import BitcoinCashValidator, verify_bitcoin_cash_auth
from token_manager import token_manager, TokenData


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
    timestamp: int
    public_key: str
    signature: str
    scopes: Optional[List[str]] = ["read"]
    domain: str = "oauth"


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


class ErrorResponse(BaseModel):
    error: str
    message: str


# Security
security = HTTPBearer(auto_error=False)


# FastAPI app
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Bitcoin Cash OAuth Server starting...")
    yield
    # Shutdown
    print("🛑 Server shutting down...")


app = FastAPI(
    title="Bitcoin Cash OAuth Server",
    description="OAuth2 server using Bitcoin Cash ECDSA signatures for authentication",
    version="1.0.0",
    lifespan=lifespan,
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> TokenData:
    """Dependency to validate access token and return user info"""
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    token_data = token_manager.validate_access_token(token)

    if not token_data:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


@app.post("/auth/register", response_model=RegisterResponse)
async def register_user(request: RegisterRequest):
    """
    Register a new user with a Bitcoin Cash address

    - If user_id is provided, it will be used (must be unique)
    - If not provided, a unique ID will be generated
    """
    # Validate CashAddr format
    is_valid, network = BitcoinCashValidator.validate_cash_address(request.address)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail="Invalid Bitcoin Cash CashAddr format. Expected format: bitcoincash:qz...",
        )

    try:
        user_id = token_manager.register_user(request.address, request.user_id)

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


@app.post("/auth/token", response_model=TokenResponse)
async def get_token(request: TokenRequest):
    """
    Obtain an OAuth token using Bitcoin Cash signature authentication

    The client must sign the message in format "bitcoincash-oauth|domain|userId|timestamp"
    with their private key and provide the public key and signature."""
    # Check if user exists
    if not token_manager.user_exists(request.user_id):
        raise HTTPException(
            status_code=404, detail="User not found. Please register first."
        )

    # Get expected address
    expected_address = token_manager.get_user_address(request.user_id)
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
        raise HTTPException(status_code=401, detail=f"Authentication failed: {reason}")

    # Create token pair
    token_data = token_manager.create_token_pair(
        user_id=request.user_id, scopes=request.scopes
    )

    return TokenResponse(
        access_token=token_data.access_token,
        token_type=token_data.token_type,
        expires_in=token_data.expires_in,
        refresh_token=token_data.refresh_token,
        scopes=token_data.scopes,
    )


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest):
    """Refresh an access token using a refresh token"""
    new_token = token_manager.refresh_access_token(request.refresh_token)

    if not new_token:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    return TokenResponse(
        access_token=new_token.access_token,
        token_type=new_token.token_type,
        expires_in=new_token.expires_in,
        refresh_token=new_token.refresh_token,
        scopes=new_token.scopes,
    )


@app.post("/auth/revoke")
async def revoke_token(request: RevokeRequest):
    """Revoke an access token"""
    success = token_manager.revoke_token(request.token)

    if not success:
        raise HTTPException(status_code=404, detail="Token not found")

    return {"message": "Token revoked successfully"}


@app.get("/auth/me")
async def get_current_user_info(token_data: TokenData = Depends(get_current_user)):
    """Get information about the currently authenticated user"""
    address = token_manager.get_user_address(token_data.user_id)

    return {
        "user_id": token_data.user_id,
        "address": address,
        "scopes": token_data.scopes,
        "expires_at": token_data.expires_at,
    }


@app.get("/api/protected")
async def protected_resource(token_data: TokenData = Depends(get_current_user)):
    """Example protected endpoint"""
    return {
        "message": "This is a protected resource",
        "user_id": token_data.user_id,
        "scopes": token_data.scopes,
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "service": "bitcoin-cash-oauth",
    }


# Run the server
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
