"""
Bitcoin Cash OAuth FastAPI - Testing Utilities
Helpers for testing OAuth-protected endpoints

Usage:
    import pytest
    from bitcoincash_oauth_fastapi.testing import OAuthTestClient
    from bitcoincash_oauth_fastapi import init_oauth, close_oauth

    @pytest.fixture
    async def client():
        await init_oauth()
        async with OAuthTestClient() as client:
            yield client
        await close_oauth()

    async def test_protected_endpoint(client):
        user = await client.create_user(wallet_hash="abc123", address="bitcoincash:...")
        token = await client.create_token(user)

        response = await client.get(
            "/api/protected",
            headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert response.status_code == 200
"""

from typing import Optional, List
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from .database import db_manager, get_db
from .config import get_settings, get_user_model, get_token_model
from .cache import cache_manager


class OAuthTestClient:
    """
    Test client for Bitcoin Cash OAuth FastAPI

    Provides utilities for creating test users and tokens
    """

    def __init__(self, app: Optional[FastAPI] = None):
        self.app = app
        self.client: Optional[AsyncClient] = None
        self.db: Optional[AsyncSession] = None

    @asynccontextmanager
    async def __aenter__(self):
        """Enter async context"""
        if self.app is None:
            # Create minimal app for testing
            from .router import create_oauth_router

            self.app = FastAPI()
            self.app.include_router(create_oauth_router())

            @self.app.on_event("startup")
            async def startup():
                await db_manager.init_db()
                await cache_manager.init()

        self.client = AsyncClient(app=self.app, base_url="http://test")

        # Get database session
        async for session in db_manager.get_session():
            self.db = session
            break

        yield self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context"""
        if self.client:
            await self.client.aclose()
        if self.db:
            await self.db.close()

    async def create_user(
        self,
        wallet_hash: str,
        address: str,
        public_key: str = "",
        is_active: bool = True,
    ):
        """
        Create a test user

        Args:
            wallet_hash: User ID (wallet hash)
            address: Bitcoin Cash address
            public_key: Optional public key
            is_active: Whether user is active

        Returns:
            User instance
        """
        user = get_user_model()(
            user_id=wallet_hash,
            bitcoin_address=address,
            public_key=public_key,
            is_active=is_active,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def create_token(
        self,
        user,
        scopes: Optional[List[str]] = None,
        expired: bool = False,
    ):
        """
        Create a test token

        Args:
            user: User to create token for
            scopes: OAuth scopes
            expired: Whether token should be expired

        Returns:
            Token instance
        """
        from datetime import timedelta

        settings = get_settings()
        now = datetime.now(timezone.utc)

        if expired:
            expires_at = now - timedelta(hours=1)
        else:
            expires_at = now + timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME)

        TokenModel = get_token_model()
        token = TokenModel(
            user_id=user.user_id,
            access_token=TokenModel.generate_token(),
            refresh_token=TokenModel.generate_token(),
            scopes=scopes or ["read"],
            expires_at=expires_at,
            refresh_expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_LIFETIME),
        )

        self.db.add(token)
        await self.db.commit()
        await self.db.refresh(token)

        return token

    async def get_auth_header(self, token) -> dict:
        """Get authorization header for a token"""
        return {"Authorization": f"Bearer {token.access_token}"}

    # HTTP method wrappers

    async def get(self, url: str, **kwargs):
        """Make GET request"""
        return await self.client.get(url, **kwargs)

    async def post(self, url: str, **kwargs):
        """Make POST request"""
        return await self.client.post(url, **kwargs)

    async def put(self, url: str, **kwargs):
        """Make PUT request"""
        return await self.client.put(url, **kwargs)

    async def delete(self, url: str, **kwargs):
        """Make DELETE request"""
        return await self.client.delete(url, **kwargs)


class MockSignatureVerifier:
    """
    Mock signature verifier for testing

    Usage:
        with MockSignatureVerifier(valid=True):
            # All signatures will be considered valid
            response = await client.post("/auth/token", json={...})
    """

    def __init__(self, valid: bool = True, address_match: bool = True):
        self.valid = valid
        self.address_match = address_match
        self.original_verify = None

    def __enter__(self):
        """Enter context manager"""
        from . import validator

        self.original_verify = validator.BitcoinCashValidator.authenticate_user

        def mock_authenticate(*args, **kwargs):
            if not self.valid:
                return False, "Invalid signature"
            if not self.address_match:
                return False, "Address mismatch"
            return True, "Authentication successful"

        validator.BitcoinCashValidator.authenticate_user = mock_authenticate
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager"""
        from . import validator

        validator.BitcoinCashValidator.authenticate_user = self.original_verify
        return False


# Pytest fixtures

import pytest


@pytest.fixture
async def oauth_test_client():
    """Pytest fixture for OAuth test client"""
    async with OAuthTestClient() as client:
        yield client


@pytest.fixture
async def test_user(oauth_test_client):
    """Pytest fixture for a test user"""
    return await oauth_test_client.create_user(
        wallet_hash="test_wallet_hash", address="bitcoincash:qz7f..."
    )


@pytest.fixture
async def test_token(oauth_test_client, test_user):
    """Pytest fixture for a test token"""
    return await oauth_test_client.create_token(test_user)


@pytest.fixture
async def auth_headers(test_token):
    """Pytest fixture for authorization headers"""
    return {"Authorization": f"Bearer {test_token.access_token}"}
