"""
Bitcoin Cash OAuth Django - Integration module
Django views and DRF integration for Bitcoin Cash OAuth
"""

from typing import Optional, List
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import json

from .validator import BitcoinCashValidator, verify_bitcoin_cash_auth
from .token_manager import token_manager, TokenData


class BitcoinCashOAuthViews:
    """Django views for Bitcoin Cash OAuth authentication"""

    def __init__(
        self,
        token_ttl: int = 3600,
        refresh_token_ttl: int = 2592000,
        max_tokens_per_user: int = 5,
        max_timestamp_diff: int = 300,
    ):
        self.token_manager = token_manager
        self.token_manager.access_token_ttl = token_ttl
        self.token_manager.refresh_token_ttl = refresh_token_ttl
        self.token_manager.max_tokens_per_user = max_tokens_per_user
        self.max_timestamp_diff = max_timestamp_diff

    @method_decorator(csrf_exempt)
    def register_view(self, request):
        """Handle user registration"""
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)

        try:
            data = json.loads(request.body)
            address = data.get("address")
            user_id = data.get("user_id")

            if not address:
                return JsonResponse({"error": "address is required"}, status=400)

            # Validate CashAddr format
            is_valid, network = BitcoinCashValidator.validate_cash_address(address)
            if not is_valid:
                return JsonResponse(
                    {
                        "error": "Invalid Bitcoin Cash CashAddr format. Expected format: bitcoincash:qz..."
                    },
                    status=400,
                )

            try:
                user_id = self.token_manager.register_user(address, user_id)

                is_new = user_id == user_id if user_id else True
                message = (
                    "User registered successfully"
                    if is_new
                    else "User already exists, returning existing ID"
                )

                return JsonResponse(
                    {"user_id": user_id, "address": address, "message": message}
                )

            except ValueError as e:
                return JsonResponse({"error": str(e)}, status=409)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    @method_decorator(csrf_exempt)
    def token_view(self, request):
        """Handle token issuance"""
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)

        try:
            data = json.loads(request.body)
            user_id = data.get("user_id")
            timestamp = data.get("timestamp")
            domain = data.get("domain", "oauth")
            public_key = data.get("public_key")
            signature = data.get("signature")
            scopes = data.get("scopes", ["read"])

            # Check if user exists
            if not self.token_manager.user_exists(user_id):
                return JsonResponse(
                    {"error": "User not found. Please register first."}, status=404
                )

            # Get expected address
            expected_address = self.token_manager.get_user_address(user_id)
            if not expected_address:
                return JsonResponse({"error": "User address not found"}, status=500)

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
                return JsonResponse(
                    {"error": f"Authentication failed: {reason}"}, status=401
                )

            # Create token pair
            token_data = self.token_manager.create_token_pair(
                user_id=user_id, scopes=scopes
            )

            return JsonResponse(
                {
                    "access_token": token_data.access_token,
                    "token_type": token_data.token_type,
                    "expires_in": token_data.expires_in,
                    "refresh_token": token_data.refresh_token,
                    "scopes": token_data.scopes,
                }
            )

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    @method_decorator(csrf_exempt)
    def refresh_view(self, request):
        """Handle token refresh"""
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)

        try:
            data = json.loads(request.body)
            refresh_token = data.get("refresh_token")

            new_token = self.token_manager.refresh_access_token(refresh_token)

            if not new_token:
                return JsonResponse(
                    {"error": "Invalid or expired refresh token"}, status=401
                )

            return JsonResponse(
                {
                    "access_token": new_token.access_token,
                    "token_type": new_token.token_type,
                    "expires_in": new_token.expires_in,
                    "refresh_token": new_token.refresh_token,
                    "scopes": new_token.scopes,
                }
            )

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    @method_decorator(csrf_exempt)
    def revoke_view(self, request):
        """Handle token revocation"""
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)

        try:
            data = json.loads(request.body)
            token = data.get("token")

            success = self.token_manager.revoke_token(token)

            if not success:
                return JsonResponse({"error": "Token not found"}, status=404)

            return JsonResponse({"message": "Token revoked successfully"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    def me_view(self, request):
        """Get current user info (requires authentication)"""
        if request.method != "GET":
            return JsonResponse({"error": "Method not allowed"}, status=405)

        # Validate token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JsonResponse(
                {"error": "Authorization header missing or invalid"}, status=401
            )

        token = auth_header[7:]  # Remove "Bearer "
        token_data = self.token_manager.validate_access_token(token)

        if not token_data:
            return JsonResponse({"error": "Invalid or expired token"}, status=401)

        address = self.token_manager.get_user_address(token_data.user_id)

        return JsonResponse(
            {
                "user_id": token_data.user_id,
                "address": address,
                "scopes": token_data.scopes,
                "expires_at": token_data.expires_at,
            }
        )


# Create singleton instance
oauth_views = BitcoinCashOAuthViews()


# Django view functions (can be used in urls.py)
@csrf_exempt
def register(request):
    """Register a new user with a Bitcoin Cash address"""
    return oauth_views.register_view(request)


@csrf_exempt
def token(request):
    """Obtain an OAuth token using Bitcoin Cash signature authentication"""
    return oauth_views.token_view(request)


@csrf_exempt
def refresh(request):
    """Refresh an access token using a refresh token"""
    return oauth_views.refresh_view(request)


@csrf_exempt
def revoke(request):
    """Revoke an access token"""
    return oauth_views.revoke_view(request)


def me(request):
    """Get information about the currently authenticated user"""
    return oauth_views.me_view(request)
