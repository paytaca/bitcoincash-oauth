"""
Bitcoin Cash OAuth Django - DRF Integration
Django REST Framework serializers, permissions, and viewsets
"""

from rest_framework import serializers, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed, NotFound, ValidationError

from .validator import BitcoinCashValidator, verify_bitcoin_cash_auth
from .token_manager import token_manager, TokenData


# Serializers
class RegisterSerializer(serializers.Serializer):
    """Serializer for user registration"""

    address = serializers.CharField(required=True)
    user_id = serializers.CharField(required=False, allow_null=True)


class RegisterResponseSerializer(serializers.Serializer):
    """Serializer for registration response"""

    user_id = serializers.CharField()
    address = serializers.CharField()
    message = serializers.CharField()


class TokenRequestSerializer(serializers.Serializer):
    """Serializer for token request"""

    user_id = serializers.CharField(required=True)
    timestamp = serializers.IntegerField(required=True)
    public_key = serializers.CharField(required=True)
    signature = serializers.CharField(required=True)
    scopes = serializers.ListField(
        child=serializers.CharField(), required=False, default=["read"]
    )


class TokenResponseSerializer(serializers.Serializer):
    """Serializer for token response"""

    access_token = serializers.CharField()
    token_type = serializers.CharField(default="bearer")
    expires_in = serializers.IntegerField()
    refresh_token = serializers.CharField()
    scopes = serializers.ListField(child=serializers.CharField())


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
                # request.token_data contains the validated TokenData
                return Response({"user_id": request.token_data.user_id})
    """

    def has_permission(self, request, view):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        token = auth_header[7:]  # Remove "Bearer "
        token_data = token_manager.validate_access_token(token)

        if not token_data:
            return False

        # Attach token data to request for use in views
        request.token_data = token_data
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
        if not hasattr(request, "token_data"):
            return False

        # Check if any of the required scopes are present
        user_scopes = set(request.token_data.scopes)
        required_scopes = set(getattr(view, "required_scopes", self.required_scopes))

        return bool(user_scopes & required_scopes)


# DRF Views
class RegisterView(APIView):
    """DRF view for user registration"""

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        address = serializer.validated_data["address"]
        user_id = serializer.validated_data.get("user_id")

        # Validate CashAddr format
        is_valid, network = BitcoinCashValidator.validate_cash_address(address)
        if not is_valid:
            raise ValidationError(
                {
                    "address": "Invalid Bitcoin Cash CashAddr format. Expected format: bitcoincash:qz..."
                }
            )

        try:
            user_id = token_manager.register_user(address, user_id)

            is_new = user_id == user_id if user_id else True
            message = (
                "User registered successfully"
                if is_new
                else "User already exists, returning existing ID"
            )

            response_serializer = RegisterResponseSerializer(
                data={"user_id": user_id, "address": address, "message": message}
            )
            response_serializer.is_valid()

            return Response(response_serializer.data)

        except ValueError as e:
            raise ValidationError({"user_id": str(e)})


class TokenView(APIView):
    """DRF view for token issuance"""

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = TokenRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        timestamp = serializer.validated_data["timestamp"]
        public_key = serializer.validated_data["public_key"]
        signature = serializer.validated_data["signature"]
        scopes = serializer.validated_data.get("scopes", ["read"])

        # Check if user exists
        if not token_manager.user_exists(user_id):
            raise NotFound("User not found. Please register first.")

        # Get expected address
        expected_address = token_manager.get_user_address(user_id)
        if not expected_address:
            raise AuthenticationFailed("User address not found")

        # Validate authentication
        is_valid, reason = verify_bitcoin_cash_auth(
            user_id=user_id,
            timestamp=timestamp,
            public_key=public_key,
            signature=signature,
            expected_address=expected_address,
        )

        if not is_valid:
            raise AuthenticationFailed(f"Authentication failed: {reason}")

        # Create token pair
        token_data = token_manager.create_token_pair(user_id=user_id, scopes=scopes)

        response_serializer = TokenResponseSerializer(
            data={
                "access_token": token_data.access_token,
                "token_type": token_data.token_type,
                "expires_in": token_data.expires_in,
                "refresh_token": token_data.refresh_token,
                "scopes": token_data.scopes,
            }
        )
        response_serializer.is_valid()

        return Response(response_serializer.data)


class RefreshView(APIView):
    """DRF view for token refresh"""

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh_token"]
        new_token = token_manager.refresh_access_token(refresh_token)

        if not new_token:
            raise AuthenticationFailed("Invalid or expired refresh token")

        response_serializer = TokenResponseSerializer(
            data={
                "access_token": new_token.access_token,
                "token_type": new_token.token_type,
                "expires_in": new_token.expires_in,
                "refresh_token": new_token.refresh_token,
                "scopes": new_token.scopes,
            }
        )
        response_serializer.is_valid()

        return Response(response_serializer.data)


class RevokeView(APIView):
    """DRF view for token revocation"""

    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        success = token_manager.revoke_token(token)

        if not success:
            raise NotFound("Token not found")

        return Response({"message": "Token revoked successfully"})


class MeView(APIView):
    """DRF view for getting current user info"""

    permission_classes = [IsBitcoinCashAuthenticated]

    def get(self, request):
        token_data = request.token_data
        address = token_manager.get_user_address(token_data.user_id)

        serializer = UserInfoSerializer(
            data={
                "user_id": token_data.user_id,
                "address": address,
                "scopes": token_data.scopes,
                "expires_at": token_data.expires_at,
            }
        )
        serializer.is_valid()

        return Response(serializer.data)
