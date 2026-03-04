"""
Bitcoin Cash OAuth Django - Testing Utilities
Helpers for testing OAuth-protected endpoints

Usage:
    from bitcoincash_oauth_django.testing import OAuthTestCase

    class MyTestCase(OAuthTestCase):
        def test_protected_endpoint(self):
            # Create a user and token
            user = self.create_oauth_user(wallet_hash='abc123', address='bitcoincash:...')
            token = self.create_access_token(user)

            # Make authenticated request
            response = self.client.get(
                '/api/endpoint',
                HTTP_AUTHORIZATION=f'Bearer {token.access_token}'
            )
            self.assertEqual(response.status_code, 200)
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

from .validator import BitcoinCashValidator
from .settings import get_settings


def _get_user_model():
    """Get the user model class lazily"""
    return get_settings().get_user_model()


def _get_token_model():
    """Get the token model class lazily"""
    return get_settings().get_token_model()


class OAuthTestCase(TestCase):
    """
    Base test case for Bitcoin Cash OAuth tests

    Provides helper methods for creating users and tokens
    """

    def setUp(self):
        """Set up test client"""
        super().setUp()
        self.client = Client()

    def create_oauth_user(self, wallet_hash, address, public_key="", **kwargs):
        """
        Create a test OAuth user

        Args:
            wallet_hash: The user_id (wallet hash)
            address: Bitcoin Cash address
            public_key: Optional public key
            **kwargs: Additional fields for the user

        Returns:
            BitcoinCashUser instance
        """
        User = get_user_model()

        user = User.objects.create_user(
            user_id=wallet_hash,
            bitcoin_address=address,
            public_key=public_key,
            **kwargs,
        )

        return user

    def create_access_token(self, user, scopes=None, expired=False):
        """
        Create a test access token

        Args:
            user: BitcoinCashUser instance
            scopes: List of scopes (default: ['read'])
            expired: Whether the token should be expired

        Returns:
            OAuthToken instance
        """
        from .settings import get_settings

        settings = get_settings()
        now = timezone.now()

        if expired:
            expires_at = now - timedelta(hours=1)
        else:
            expires_at = now + timedelta(seconds=settings.access_token_lifetime)

        token = _get_token_model().objects.create(
            user=user,
            access_token=_get_token_model().generate_token(),
            refresh_token=_get_token_model().generate_token(),
            scopes=scopes or ["read"],
            expires_at=expires_at,
            refresh_expires_at=now + timedelta(seconds=settings.refresh_token_lifetime),
        )

        return token

    def create_expired_token(self, user, scopes=None):
        """Create an expired access token"""
        return self.create_access_token(user, scopes=scopes, expired=True)

    def get_auth_header(self, token):
        """
        Get the Authorization header for a token

        Args:
            token: OAuthToken instance or token string

        Returns:
            dict: Authorization header
        """
        if isinstance(token, OAuthToken):
            token_str = token.access_token
        else:
            token_str = token

        return {"HTTP_AUTHORIZATION": f"Bearer {token_str}"}

    def assertOAuthSuccess(self, response):
        """Assert that an OAuth request succeeded"""
        self.assertIn(
            response.status_code,
            [200, 201],
            f"Expected success, got {response.status_code}: {response.content}",
        )

    def assertOAuthUnauthorized(self, response):
        """Assert that an OAuth request was unauthorized"""
        self.assertEqual(
            response.status_code,
            401,
            f"Expected 401, got {response.status_code}: {response.content}",
        )

    def assertOAuthForbidden(self, response):
        """Assert that an OAuth request was forbidden"""
        self.assertEqual(
            response.status_code,
            403,
            f"Expected 403, got {response.status_code}: {response.content}",
        )


def mock_valid_address(address="bitcoincash:qz7f...", network="mainnet"):
    """
    Create a mock valid address for testing

    Returns a tuple (is_valid, network) as would be returned by validate_cash_address
    """
    return True, network


def mock_invalid_address():
    """
    Create a mock invalid address for testing

    Returns a tuple (is_valid, network) as would be returned by validate_cash_address
    """
    return False, None


class MockSignatureVerifier:
    """
    Mock signature verifier for testing

    Usage:
        with MockSignatureVerifier(valid=True):
            # All signatures will be considered valid
            response = self.client.post('/auth/token', data=...)
    """

    def __init__(self, valid=True, address_match=True):
        self.valid = valid
        self.address_match = address_match
        self.original_verify = None

    def __enter__(self):
        """Enter the context manager"""
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
        """Exit the context manager"""
        from . import validator

        validator.BitcoinCashValidator.authenticate_user = self.original_verify
        return False
