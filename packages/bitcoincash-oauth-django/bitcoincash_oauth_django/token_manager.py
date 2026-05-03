"""
Bitcoin Cash OAuth Django - Token management module
OAuth token management for Bitcoin Cash authentication using Django ORM
"""

import time
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Set, List
from dataclasses import dataclass, field
from django.db import models


@dataclass
class TokenData:
    """OAuth token data structure"""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # 1 hour default
    user_id: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    scopes: list = field(default_factory=list)


class TokenManager:
    """Manages OAuth tokens using Django ORM models"""

    def __init__(
        self,
        access_token_ttl: int = 3600,  # 1 hour
        refresh_token_ttl: int = 86400 * 30,  # 30 days
        max_tokens_per_user: int = 5,
    ):
        self.access_token_ttl = access_token_ttl
        self.refresh_token_ttl = refresh_token_ttl
        self.max_tokens_per_user = max_tokens_per_user

    def _get_models(self):
        """Lazy import Django models to avoid AppRegistryNotReady"""
        from .models import BitcoinCashUser, OAuthToken
        return BitcoinCashUser, OAuthToken

    def register_user(
        self, bitcoincash_address: str, user_id: Optional[str] = None
    ) -> str:
        """Register a new user with a Bitcoin Cash address"""
        BitcoinCashUser, OAuthToken = self._get_models()

        # Check if user already exists
        existing_user = BitcoinCashUser.objects.filter(
            models.Q(bitcoincash_address=bitcoincash_address) | models.Q(user_id=user_id)
        ).first()
        
        if existing_user:
            return existing_user.user_id

        # Use provided ID or generate one
        if user_id is None:
            user_id = f"user_{uuid.uuid4().hex[:16]}"

        user = BitcoinCashUser.objects.create(
            user_id=user_id,
            bitcoincash_address=bitcoincash_address,
        )

        return user.user_id

    def get_user_address(self, user_id: str) -> Optional[str]:
        """Get the Bitcoin Cash address for a user"""
        BitcoinCashUser, OAuthToken = self._get_models()
        try:
            user = BitcoinCashUser.objects.get(user_id=user_id)
            return user.bitcoincash_address
        except BitcoinCashUser.DoesNotExist:
            return None

    def user_exists(self, user_id: str) -> bool:
        """Check if a user exists"""
        BitcoinCashUser, OAuthToken = self._get_models()
        return BitcoinCashUser.objects.filter(user_id=user_id).exists()

    def create_token_pair(
        self, user_id: str, scopes: Optional[list] = None
    ) -> TokenData:
        """Create a new access token and refresh token pair"""
        BitcoinCashUser, OAuthToken = self._get_models()
        from django.utils import timezone

        # Get user
        try:
            user = BitcoinCashUser.objects.get(user_id=user_id)
        except BitcoinCashUser.DoesNotExist:
            raise ValueError(f"User '{user_id}' not found")

        # Clean up old tokens if exceeding max
        active_tokens = OAuthToken.objects.filter(
            user=user,
            is_revoked=False,
            expires_at__gt=timezone.now()
        ).count()

        if active_tokens >= self.max_tokens_per_user:
            # Revoke oldest token
            oldest = OAuthToken.objects.filter(
                user=user,
                is_revoked=False
            ).order_by('created_at').first()
            if oldest:
                oldest.revoke()

        # Generate tokens
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        now = timezone.now()

        # Create token in database
        token = OAuthToken.objects.create(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token,
            scopes=scopes or ["read"],
            expires_at=now + timedelta(seconds=self.access_token_ttl),
            refresh_expires_at=now + timedelta(seconds=self.refresh_token_ttl),
        )

        return TokenData(
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            token_type=token.token_type,
            expires_in=int((token.expires_at - now).total_seconds()),
            user_id=user_id,
            created_at=now.timestamp(),
            expires_at=token.expires_at.timestamp(),
            scopes=token.scopes,
        )

    def validate_access_token(self, access_token: str) -> Optional[TokenData]:
        """Validate an access token"""
        BitcoinCashUser, OAuthToken = self._get_models()

        token = OAuthToken.validate_access_token(access_token)
        if not token:
            return None

        return TokenData(
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            token_type=token.token_type,
            expires_in=token.expires_in,
            user_id=token.user.user_id,
            created_at=token.created_at.timestamp(),
            expires_at=token.expires_at.timestamp(),
            scopes=token.scopes,
        )

    def refresh_access_token(self, refresh_token: str) -> Optional[TokenData]:
        """Refresh an access token using a refresh token"""
        BitcoinCashUser, OAuthToken = self._get_models()
        from django.utils import timezone

        token = OAuthToken.validate_refresh_token(refresh_token)
        if not token:
            return None

        # Revoke old token
        token.revoke()

        # Create new token pair
        return self.create_token_pair(token.user.user_id, token.scopes)

    def revoke_token(self, access_token: str) -> bool:
        """Revoke an access token"""
        BitcoinCashUser, OAuthToken = self._get_models()

        try:
            token = OAuthToken.objects.get(access_token=access_token)
            token.revoke()
            return True
        except OAuthToken.DoesNotExist:
            return False

    def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke all tokens for a user"""
        BitcoinCashUser, OAuthToken = self._get_models()
        from django.utils import timezone

        return OAuthToken.objects.filter(
            user__user_id=user_id,
            is_revoked=False
        ).update(
            is_revoked=True,
            revoked_at=timezone.now()
        )

    def cleanup_expired_tokens(self) -> int:
        """Remove all expired tokens"""
        BitcoinCashUser, OAuthToken = self._get_models()

        return OAuthToken.cleanup_expired_tokens()

    def get_token_info(self, access_token: str) -> Optional[Dict]:
        """Get information about a token"""
        token = self.validate_access_token(access_token)
        if not token:
            return None

        return {
            "user_id": token.user_id,
            "created_at": datetime.fromtimestamp(token.created_at).isoformat(),
            "expires_at": datetime.fromtimestamp(token.expires_at).isoformat(),
            "scopes": token.scopes,
            "token_type": token.token_type,
        }


# Singleton instance for the application
token_manager = TokenManager()
