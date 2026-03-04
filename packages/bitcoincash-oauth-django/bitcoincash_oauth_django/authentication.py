"""
Bitcoin Cash OAuth Django - Authentication Backend
Django authentication backend integration
"""

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

from .models import OAuthToken
from .exceptions import InvalidTokenError, TokenExpiredError, RevokedTokenError


class BitcoinCashOAuthBackend(BaseBackend):
    """
    Django authentication backend for Bitcoin Cash OAuth

    Usage:
        AUTHENTICATION_BACKENDS = [
            'bitcoincash_oauth_django.authentication.BitcoinCashOAuthBackend',
            'django.contrib.auth.backends.ModelBackend',
        ]
    """

    def authenticate(self, request, token=None, **kwargs):
        """
        Authenticate using an OAuth token

        Args:
            request: Django request object
            token: The access token to validate

        Returns:
            User object if valid, None otherwise
        """
        if token is None:
            return None

        try:
            # Validate the token
            oauth_token = OAuthToken.validate_access_token(token)

            if oauth_token is None:
                return None

            # Get the user
            user = oauth_token.user

            # Update last login
            from django.utils import timezone

            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])

            # Attach token data to user for use in views
            user.oauth_token = oauth_token
            user.oauth_scopes = oauth_token.scopes

            return user

        except Exception:
            return None

    def get_user(self, user_id):
        """
        Get a user by their user_id

        Args:
            user_id: The user_id (wallet hash) to look up

        Returns:
            User object if found, None otherwise
        """
        User = get_user_model()

        try:
            return User.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None


class BitcoinCashModelBackend(BaseBackend):
    """
    Alternative backend that checks token scope permissions

    This backend can be used when you want to check scopes as Django permissions
    """

    def authenticate(self, request, token=None, **kwargs):
        """Authenticate using an OAuth token"""
        if token is None:
            return None

        try:
            oauth_token = OAuthToken.validate_access_token(token)

            if oauth_token is None:
                return None

            user = oauth_token.user

            # Update last login
            from django.utils import timezone

            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])

            # Attach OAuth info
            user.oauth_token = oauth_token
            user.oauth_scopes = oauth_token.scopes

            return user

        except Exception:
            return None

    def get_user(self, user_id):
        """Get a user by their user_id"""
        User = get_user_model()

        try:
            return User.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None

    def has_perm(self, user_obj, perm, obj=None):
        """
        Check if user has a permission

        Maps Django permissions to OAuth scopes:
        - 'oauth.read' -> 'read' scope
        - 'oauth.write' -> 'write' scope
        - 'oauth.admin' -> 'admin' scope
        """
        if not hasattr(user_obj, "oauth_scopes"):
            return False

        # Map Django permissions to OAuth scopes
        scope_map = {
            "oauth.read": "read",
            "oauth.write": "write",
            "oauth.admin": "admin",
        }

        required_scope = scope_map.get(perm)
        if required_scope:
            return required_scope in user_obj.oauth_scopes

        return False
