"""
Bitcoin Cash OAuth FastAPI - Token management module
OAuth token management for Bitcoin Cash authentication
"""

import time
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Set
from dataclasses import dataclass, field


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
    """Manages OAuth tokens for authenticated users"""

    def __init__(
        self,
        access_token_ttl: int = 3600,  # 1 hour
        refresh_token_ttl: int = 86400 * 30,  # 30 days
        max_tokens_per_user: int = 5,
    ):
        self.access_token_ttl = access_token_ttl
        self.refresh_token_ttl = refresh_token_ttl
        self.max_tokens_per_user = max_tokens_per_user

        # Storage (in production, use Redis or database)
        self._tokens: Dict[str, TokenData] = {}  # access_token -> TokenData
        self._refresh_tokens: Dict[str, str] = {}  # refresh_token -> access_token
        self._user_tokens: Dict[str, Set[str]] = {}  # user_id -> set of access_tokens
        self._revoked_tokens: Set[str] = set()
        self._address_to_user: Dict[str, str] = {}  # bitcoin_address -> user_id
        self._user_to_address: Dict[str, str] = {}  # user_id -> bitcoin_address

    def _generate_token(self) -> str:
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(32)

    def _generate_user_id(self) -> str:
        """Generate a unique user ID"""
        return f"user_{uuid.uuid4().hex[:16]}"

    def register_user(self, bitcoin_address: str, user_id: Optional[str] = None) -> str:
        """
        Register a new user with a Bitcoin Cash address

        Args:
            bitcoin_address: The Bitcoin Cash address
            user_id: Optional user-provided ID (if None, generates one)

        Returns:
            The user_id
        """
        # Check if address already registered
        if bitcoin_address in self._address_to_user:
            return self._address_to_user[bitcoin_address]

        # Use provided ID or generate one
        if user_id is None:
            user_id = self._generate_user_id()
        elif user_id in self._user_to_address:
            raise ValueError(f"User ID '{user_id}' already exists")

        # Store mappings
        self._address_to_user[bitcoin_address] = user_id
        self._user_to_address[user_id] = bitcoin_address
        self._user_tokens[user_id] = set()

        return user_id

    def get_user_address(self, user_id: str) -> Optional[str]:
        """Get the Bitcoin Cash address for a user"""
        return self._user_to_address.get(user_id)

    def user_exists(self, user_id: str) -> bool:
        """Check if a user exists"""
        return user_id in self._user_to_address

    def create_token_pair(
        self, user_id: str, scopes: Optional[list] = None
    ) -> TokenData:
        """
        Create a new access token and refresh token pair

        Args:
            user_id: The user identifier
            scopes: Optional list of OAuth scopes

        Returns:
            TokenData containing both tokens
        """
        # Clean up old tokens for this user if exceeding max
        if user_id in self._user_tokens:
            user_token_set = self._user_tokens[user_id]
            if len(user_token_set) >= self.max_tokens_per_user:
                # Remove oldest token
                oldest_token = min(
                    user_token_set, key=lambda t: self._tokens[t].created_at
                )
                self.revoke_token(oldest_token)

        # Generate tokens
        access_token = self._generate_token()
        refresh_token = self._generate_token()

        now = time.time()

        token_data = TokenData(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user_id,
            created_at=now,
            expires_at=now + self.access_token_ttl,
            scopes=scopes or ["read"],
        )

        # Store tokens
        self._tokens[access_token] = token_data
        self._refresh_tokens[refresh_token] = access_token

        # Track user's tokens
        if user_id not in self._user_tokens:
            self._user_tokens[user_id] = set()
        self._user_tokens[user_id].add(access_token)

        return token_data

    def validate_access_token(self, access_token: str) -> Optional[TokenData]:
        """
        Validate an access token

        Returns:
            TokenData if valid, None otherwise
        """
        # Check if revoked
        if access_token in self._revoked_tokens:
            return None

        # Check if exists
        if access_token not in self._tokens:
            return None

        token_data = self._tokens[access_token]

        # Check expiration
        if time.time() > token_data.expires_at:
            # Clean up expired token
            self.revoke_token(access_token)
            return None

        return token_data

    def refresh_access_token(self, refresh_token: str) -> Optional[TokenData]:
        """
        Refresh an access token using a refresh token

        Args:
            refresh_token: The refresh token

        Returns:
            New TokenData if successful, None otherwise
        """
        # Check if refresh token exists
        if refresh_token not in self._refresh_tokens:
            return None

        # Get the old access token
        old_access_token = self._refresh_tokens[refresh_token]

        # Check if it was revoked
        if old_access_token in self._revoked_tokens:
            return None

        # Get old token data
        old_token_data = self._tokens.get(old_access_token)
        if not old_token_data:
            return None

        user_id = old_token_data.user_id
        scopes = old_token_data.scopes

        # Revoke old tokens
        self.revoke_token(old_access_token)
        del self._refresh_tokens[refresh_token]

        # Create new token pair
        return self.create_token_pair(user_id, scopes)

    def revoke_token(self, access_token: str) -> bool:
        """
        Revoke an access token

        Returns:
            True if token was revoked, False if not found
        """
        if access_token not in self._tokens:
            return False

        token_data = self._tokens[access_token]
        user_id = token_data.user_id

        # Remove from user's token set
        if user_id in self._user_tokens:
            self._user_tokens[user_id].discard(access_token)

        # Mark as revoked
        self._revoked_tokens.add(access_token)

        # Clean up from active tokens
        del self._tokens[access_token]

        # Clean up associated refresh token
        for rt, at in list(self._refresh_tokens.items()):
            if at == access_token:
                del self._refresh_tokens[rt]
                break

        return True

    def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user

        Returns:
            Number of tokens revoked
        """
        if user_id not in self._user_tokens:
            return 0

        tokens_to_revoke = list(self._user_tokens[user_id])
        count = 0

        for token in tokens_to_revoke:
            if self.revoke_token(token):
                count += 1

        return count

    def cleanup_expired_tokens(self) -> int:
        """
        Remove all expired tokens from storage

        Returns:
            Number of tokens cleaned up
        """
        now = time.time()
        expired_tokens = [
            token for token, data in self._tokens.items() if now > data.expires_at
        ]

        for token in expired_tokens:
            self.revoke_token(token)

        return len(expired_tokens)

    def get_token_info(self, access_token: str) -> Optional[Dict]:
        """Get information about a token"""
        token_data = self.validate_access_token(access_token)
        if not token_data:
            return None

        return {
            "user_id": token_data.user_id,
            "created_at": datetime.fromtimestamp(token_data.created_at).isoformat(),
            "expires_at": datetime.fromtimestamp(token_data.expires_at).isoformat(),
            "scopes": token_data.scopes,
            "token_type": token_data.token_type,
        }


# Singleton instance for the application
token_manager = TokenManager()
