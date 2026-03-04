"""
Bitcoin Cash OAuth Django - Updated DRF Integration
Django REST Framework views with database persistence and signature-based registration
"""

import time
from rest_framework import serializers, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import (
    AuthenticationFailed,
    NotFound,
    ValidationError,
    PermissionDenied,
)

from .validator import BitcoinCashValidator, verify_bitcoin_cash_auth
from .signals import (
    token_created,
    token_refreshed,
    token_revoked,
    user_registered,
    user_authenticated,
    authentication_failed,
    registration_failed,
)
from .exceptions import (
    BitcoinCashAuthError,
    InvalidSignatureError,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidAddressError,
    RegistrationError,
)
from .utils import create_registration_message
from .settings import get_settings


# Lazy model loading helpers to avoid AppRegistryNotReady
def _get_user_model():
    """Get the user model class lazily"""
    return get_settings().get_user_model()


def _get_token_model():
    """Get the token model class lazily"""
    return get_settings().get_token_model()


# Serializers
class RegisterSerializer(serializers.Serializer):
    """Serializer for user registration with signature verification"""

    address = serializers.CharField(
        required=True, help_text="Bitcoin Cash CashAddr address"
    )
    user_id = serializers.CharField(
        required=False, allow_null=True, help_text="Optional user-provided ID"
    )
    # Signature fields for secure registration
    timestamp = serializers.IntegerField(
        required=False, help_text="Unix timestamp for signature"
    )
    domain = serializers.CharField(
        required=False, default="oauth", help_text="Domain for message binding"
    )
    public_key = serializers.CharField(
        required=False, help_text="Hex-encoded public key"
    )
    signature = serializers.CharField(required=False, help_text="DER-encoded signature")


class RegisterResponseSerializer(serializers.Serializer):
    """Serializer for registration response"""

    user_id = serializers.CharField()
    address = serializers.CharField()
    message = serializers.CharField()
    signature_required = serializers.BooleanField(required=False)


class TokenRequestSerializer(serializers.Serializer):
    """Serializer for token request"""

    user_id = serializers.CharField(required=True)
    timestamp = serializers.IntegerField(required=True)
    domain = serializers.CharField(required=False, default="oauth")
    public_key = serializers.CharField(required=True)
    signature = serializers.CharField(required=True)
    scopes = serializers.ListField(
        child=serializers.CharField(), required=False, default=["read"]
    )


class TokenResponseSerializer(serializers.Serializer):
    """Serializer for token response - standardized format"""

    access_token = serializers.CharField()
    token_type = serializers.CharField(default="Bearer")
    expires_in = serializers.IntegerField()
    refresh_token = serializers.CharField()
    scopes = serializers.ListField(child=serializers.CharField())
    user_id = serializers.CharField()


class RefreshSerializer(serializers.Serializer):
    """Serializer for refresh request"""

    refresh_token = serializers.CharField(required=True)


class RevokeSerializer(serializers.Serializer):
    """Serializer for revoke request"""

    token = serializers.CharField(required=True)


class UserInfoSerializer(serializers.Serializer):
    """Serializer for user info response"""

    user_id = serializers.CharField()
    address = serializers.CharField()
    scopes = serializers.ListField(child=serializers.CharField())
    expires_at = serializers.FloatField()


# Permissions
class IsBitcoinCashAuthenticated(permissions.BasePermission):
    """
    DRF Permission class that validates Bitcoin Cash OAuth tokens

    Usage:
        class MyView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated]

            def get(self, request):
                # request.user contains the BitcoinCashUser
                # request.oauth_scopes contains the scopes
                return Response({"user_id": request.user.user_id})
    """

    def has_permission(self, request, view):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        token = auth_header[7:]  # Remove "Bearer "
        oauth_token = _get_token_model().validate_access_token(token)

        if not oauth_token:
            return False

        # Attach token data to request for use in views
        request.token_data = oauth_token
        request.oauth_scopes = oauth_token.scopes
        request.user = oauth_token.user
        return True


class HasScope(permissions.BasePermission):
    """
    DRF Permission class that checks for specific OAuth scopes

    Usage:
        class MyView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, HasScope]
            required_scopes = ["write", "admin"]
    """

    required_scopes = ["read"]

    def has_permission(self, request, view):
        if not hasattr(request, "oauth_scopes"):
            return False

        user_scopes = set(request.oauth_scopes)
        required_scopes = set(getattr(view, "required_scopes", self.required_scopes))

        return bool(user_scopes & required_scopes)


class IsOwner(permissions.BasePermission):
    """
    Permission that checks if the user is accessing their own resource

    Usage:
        class MyView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, IsOwner]

            def get(self, request, user_id):
                # Will only allow if request.user.user_id == user_id
                pass
    """

    def has_permission(self, request, view):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        # Check URL parameter
        user_id_param = view.kwargs.get("user_id") or view.kwargs.get("pk")
        if user_id_param:
            return request.user.user_id == user_id_param

        # Check query parameter
        user_id_query = request.query_params.get("user_id")
        if user_id_query:
            return request.user.user_id == user_id_query

        return True


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Write operations require ownership, read is public

    Usage:
        class MyView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, IsOwnerOrReadOnly]
    """

    def has_permission(self, request, view):
        # Allow read-only methods
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write methods require authentication and ownership
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        user_id_param = view.kwargs.get("user_id") or view.kwargs.get("pk")
        if user_id_param:
            return request.user.user_id == user_id_param

        return True


# DRF Views
class RegisterView(APIView):
    """
    DRF view for user registration with optional signature verification

    POST /auth/register
    {
        "address": "bitcoincash:qz...",
        "user_id": "optional_wallet_hash",
        "timestamp": 1234567890,  # Required if signature verification enabled
        "domain": "oauth",        # Optional
        "public_key": "02...",    # Required if signature verification enabled
        "signature": "3045..."    # Required if signature verification enabled
    }
    """

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        address = serializer.validated_data["address"]
        user_id = serializer.validated_data.get("user_id")

        settings = get_settings()

        # Validate CashAddr format
        is_valid, network = BitcoinCashValidator.validate_cash_address(address)
        if not is_valid:
            raise ValidationError(
                {
                    "address": "Invalid Bitcoin Cash CashAddr format. Expected format: bitcoincash:qz..."
                }
            )

        # Check if signature verification is required
        if settings.REQUIRE_SIGNATURE_FOR_REGISTRATION:
            timestamp = serializer.validated_data.get("timestamp")
            public_key = serializer.validated_data.get("public_key")
            signature = serializer.validated_data.get("signature")
            domain = serializer.validated_data.get("domain", "oauth")

            if not all([timestamp, public_key, signature]):
                return Response(
                    {
                        "error": "Signature verification required",
                        "message": "Registration requires signature verification. Please provide timestamp, public_key, and signature.",
                        "signature_required": True,
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Verify signature
            is_valid_sig, reason = verify_bitcoin_cash_auth(
                user_id=user_id or address,  # Use address as fallback if no user_id
                timestamp=timestamp,
                public_key=public_key,
                signature=signature,
                expected_address=address,
                domain=domain,
            )

            if not is_valid_sig:
                authentication_failed.send(
                    sender=self.__class__,
                    user_id=user_id,
                    reason=f"Registration signature failed: {reason}",
                    request=request,
                )
                raise AuthenticationFailed(f"Signature verification failed: {reason}")

        # Check if user already exists
        if user_id and _get_user_model().objects.filter(user_id=user_id).exists():
            registration_failed.send(
                sender=self.__class__,
                address=address,
                reason=f"User ID already exists: {user_id}",
                request=request,
            )
            raise ValidationError({"user_id": "User ID already exists"})

        if _get_user_model().objects.filter(bitcoin_address=address).exists():
            existing = _get_user_model().objects.get(bitcoin_address=address)
            return Response(
                {
                    "user_id": existing.user_id,
                    "address": address,
                    "message": "User already exists, returning existing ID",
                }
            )

        try:
            # Create user
            user = _get_user_model().objects.create_user(
                user_id=user_id,
                bitcoin_address=address,
                public_key=serializer.validated_data.get("public_key", ""),
            )

            # Send signal
            user_registered.send(sender=self.__class__, user=user, request=request)

            response_serializer = RegisterResponseSerializer(
                data={
                    "user_id": user.user_id,
                    "address": address,
                    "message": "User registered successfully",
                }
            )
            response_serializer.is_valid()

            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            registration_failed.send(
                sender=self.__class__, address=address, reason=str(e), request=request
            )
            raise ValidationError({"error": str(e)})


class TokenView(APIView):
    """
    DRF view for token issuance with database persistence

    POST /auth/token
    {
        "user_id": "wallet_hash",
        "timestamp": 1234567890,
        "domain": "oauth",
        "public_key": "02...",
        "signature": "3045...",
        "scopes": ["read", "write"]
    }

    Response:
    {
        "access_token": "...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "...",
        "scopes": ["read", "write"],
        "user_id": "wallet_hash"
    }
    """

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = TokenRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        timestamp = serializer.validated_data["timestamp"]
        domain = serializer.validated_data.get("domain", "oauth")
        public_key = serializer.validated_data["public_key"]
        signature = serializer.validated_data["signature"]
        scopes = serializer.validated_data.get("scopes", ["read"])

        # Check if user exists
        try:
            user = _get_user_model().objects.get(user_id=user_id)
        except _get_user_model().DoesNotExist:
            authentication_failed.send(
                sender=self.__class__,
                user_id=user_id,
                reason="User not found",
                request=request,
            )
            raise NotFound("User not found. Please register first.")

        # Get expected address
        expected_address = user.bitcoin_address

        # Validate authentication
        is_valid, reason = verify_bitcoin_cash_auth(
            user_id=user_id,
            timestamp=timestamp,
            public_key=public_key,
            signature=signature,
            expected_address=expected_address,
            domain=domain,
        )

        if not is_valid:
            authentication_failed.send(
                sender=self.__class__, user_id=user_id, reason=reason, request=request
            )
            raise AuthenticationFailed(f"Authentication failed: {reason}")

        # Update user's public key if provided
        if public_key and not user.public_key:
            user.public_key = public_key
            user.save(update_fields=["public_key"])

        # Update last login
        from django.utils import timezone

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        # Create token pair with request info
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")[:255]

        token = _get_token_model().create_token_pair(
            user=user, scopes=scopes, ip_address=ip_address, user_agent=user_agent
        )

        # Send signal
        token_created.send(
            sender=self.__class__, user=user, token=token, request=request
        )

        user_authenticated.send(
            sender=self.__class__, user=user, token=token, request=request
        )

        response_serializer = TokenResponseSerializer(
            data={
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "refresh_token": token.refresh_token,
                "scopes": token.scopes,
                "user_id": user.user_id,
            }
        )
        response_serializer.is_valid()

        return Response(response_serializer.data)

    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class RefreshView(APIView):
    """
    DRF view for token refresh with rotation

    POST /auth/refresh
    {
        "refresh_token": "..."
    }
    """

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh_token"]

        # Validate refresh token
        old_token = _get_token_model().validate_refresh_token(refresh_token)

        if not old_token:
            raise AuthenticationFailed("Invalid or expired refresh token")

        user = old_token.user
        scopes = old_token.scopes

        # Revoke old token
        old_token.revoke()

        # Create new token pair (rotation)
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")[:255]

        new_token = _get_token_model().create_token_pair(
            user=user, scopes=scopes, ip_address=ip_address, user_agent=user_agent
        )

        # Send signal
        token_refreshed.send(
            sender=self.__class__,
            user=user,
            old_token=old_token,
            new_token=new_token,
            request=request,
        )

        response_serializer = TokenResponseSerializer(
            data={
                "access_token": new_token.access_token,
                "token_type": new_token.token_type,
                "expires_in": new_token.expires_in,
                "refresh_token": new_token.refresh_token,
                "scopes": new_token.scopes,
                "user_id": user.user_id,
            }
        )
        response_serializer.is_valid()

        return Response(response_serializer.data)

    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class RevokeView(APIView):
    """
    DRF view for token revocation with blacklist support

    POST /auth/revoke
    {
        "token": "access_token_to_revoke"
    }

    The revoked token is added to a blacklist for immediate invalidation
    across all workers (even before database replication completes).
    """

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        from django.core.cache import cache
        from datetime import timedelta

        serializer = RevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]

        # Find and revoke token
        oauth_token = _get_token_model().validate_access_token(token)

        if not oauth_token:
            # Try to find it anyway (might be expired)
            try:
                oauth_token = _get_token_model().objects.get(access_token=token)
            except _get_token_model().DoesNotExist:
                raise NotFound("Token not found")

        user = oauth_token.user

        # Calculate how long to blacklist (until token would naturally expire)
        if oauth_token.expires_at:
            from django.utils import timezone

            expires_in = (oauth_token.expires_at - timezone.now()).total_seconds()
            blacklist_duration = max(int(expires_in), 3600)  # Min 1 hour
        else:
            blacklist_duration = 86400  # 24 hours default

        # Revoke in database
        oauth_token.revoke()

        # Add to blacklist for immediate effect across all workers
        blacklist_key = f"bitcoincash_token_blacklist_{token[:32]}"
        cache.set(blacklist_key, True, blacklist_duration)

        # Also blacklist the refresh token
        if oauth_token.refresh_token:
            refresh_blacklist_key = (
                f"bitcoincash_token_blacklist_{oauth_token.refresh_token[:32]}"
            )
            cache.set(
                refresh_blacklist_key, True, blacklist_duration * 7
            )  # Refresh tokens live longer

        # Send signal
        token_revoked.send(
            sender=self.__class__, user=user, token=oauth_token, request=request
        )

        return Response(
            {
                "message": "Token revoked successfully",
                "user_id": user.user_id,
                "revoked_at": timezone.now().isoformat(),
            }
        )


class MeView(APIView):
    """
    DRF view for getting current user info

    GET /auth/me
    Authorization: Bearer <token>
    """

    permission_classes = [IsBitcoinCashAuthenticated]

    def get(self, request):
        token = request.token_data
        user = token.user

        serializer = UserInfoSerializer(
            data={
                "user_id": user.user_id,
                "address": user.bitcoin_address,
                "scopes": token.scopes,
                "expires_at": token.expires_at.timestamp(),
            }
        )
        serializer.is_valid()

        return Response(serializer.data)
