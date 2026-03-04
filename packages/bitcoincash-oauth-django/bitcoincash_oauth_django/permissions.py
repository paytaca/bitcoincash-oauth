"""
Bitcoin Cash OAuth Django - Permissions
Reusable permission classes for common patterns

Usage:
    from bitcoincash_oauth_django.permissions import (
        HasScope,
        IsOwner,
        IsOwnerOrReadOnly,
        HasWalletAddress,
    )

    class MyView(APIView):
        permission_classes = [IsBitcoinCashAuthenticated, HasScope]
        required_scopes = ['write']
"""

from rest_framework import permissions


class HasScope(permissions.BasePermission):
    """
    Permission that checks for specific OAuth scopes

    Usage:
        class MyView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, HasScope]
            required_scopes = ['write', 'admin']  # OR logic - any one is sufficient
    """

    required_scopes = ["read"]

    def has_permission(self, request, view):
        if not hasattr(request, "oauth_scopes"):
            return False

        user_scopes = set(request.oauth_scopes)
        required_scopes = set(getattr(view, "required_scopes", self.required_scopes))

        # OR logic - user needs at least one of the required scopes
        return bool(user_scopes & required_scopes)


class HasAllScopes(permissions.BasePermission):
    """
    Permission that requires ALL specified scopes (AND logic)

    Usage:
        class MyView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, HasAllScopes]
            required_scopes = ['read', 'write']  # AND logic - both required
    """

    required_scopes = ["read"]

    def has_permission(self, request, view):
        if not hasattr(request, "oauth_scopes"):
            return False

        user_scopes = set(request.oauth_scopes)
        required_scopes = set(getattr(view, "required_scopes", self.required_scopes))

        # AND logic - user needs all of the required scopes
        return required_scopes.issubset(user_scopes)


class HasReadScope(permissions.BasePermission):
    """Permission that requires 'read' scope"""

    def has_permission(self, request, view):
        if not hasattr(request, "oauth_scopes"):
            return False
        return "read" in request.oauth_scopes


class HasWriteScope(permissions.BasePermission):
    """Permission that requires 'write' scope"""

    def has_permission(self, request, view):
        if not hasattr(request, "oauth_scopes"):
            return False
        return "write" in request.oauth_scopes


class HasAdminScope(permissions.BasePermission):
    """Permission that requires 'admin' scope"""

    def has_permission(self, request, view):
        if not hasattr(request, "oauth_scopes"):
            return False
        return "admin" in request.oauth_scopes


class IsOwner(permissions.BasePermission):
    """
    Permission that checks if the user is accessing their own resource

    The view should provide the user_id in one of these ways:
    - URL parameter: user_id or pk
    - Query parameter: user_id

    Usage:
        # In URL pattern:
        path('users/<str:user_id>/transactions', TransactionView.as_view())

        # In view:
        class TransactionView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, IsOwner]

            def get_queryset(self):
                # Automatically filtered by the wallet hash from token
                return Transaction.objects.filter(wallet_hash=self.request.user.user_id)
    """

    def has_permission(self, request, view):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        # Get target user_id from URL or query params
        target_user_id = (
            view.kwargs.get("user_id")
            or view.kwargs.get("pk")
            or request.query_params.get("user_id")
        )

        if target_user_id:
            return request.user.user_id == target_user_id

        # If no target specified, assume access to own resources is allowed
        return True


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Write operations require ownership, read is public

    Usage:
        class UserProfileView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, IsOwnerOrReadOnly]

            def get(self, request, user_id):
                # Anyone authenticated can read
                pass

            def put(self, request, user_id):
                # Only owner can update
                pass
    """

    def has_permission(self, request, view):
        # Allow read-only methods
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write methods require authentication and ownership
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        target_user_id = (
            view.kwargs.get("user_id")
            or view.kwargs.get("pk")
            or request.query_params.get("user_id")
        )

        if target_user_id:
            return request.user.user_id == target_user_id

        return True


class HasWalletAddress(permissions.BasePermission):
    """
    Permission that requires the user to have a Bitcoin Cash address registered

    Usage:
        class PaymentView(APIView):
            permission_classes = [IsBitcoinCashAuthenticated, HasWalletAddress]

            def post(self, request):
                # User has a BCH address, can proceed
                address = request.user.bitcoincash_address
                pass
    """

    def has_permission(self, request, view):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        return bool(
            hasattr(request.user, "bitcoincash_address")
            and request.user.bitcoincash_address
        )


class IsStaff(permissions.BasePermission):
    """Permission that requires staff status"""

    def has_permission(self, request, view):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        return request.user.is_staff


class IsSuperUser(permissions.BasePermission):
    """Permission that requires superuser status"""

    def has_permission(self, request, view):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        return request.user.is_superuser


# Import the base authentication permission from drf_views
from .drf_views import IsBitcoinCashAuthenticated

__all__ = [
    # Base
    "IsBitcoinCashAuthenticated",
    # Scope-based
    "HasScope",
    "HasAllScopes",
    "HasReadScope",
    "HasWriteScope",
    "HasAdminScope",
    # Ownership
    "IsOwner",
    "IsOwnerOrReadOnly",
    # Requirements
    "HasWalletAddress",
    # Admin
    "IsStaff",
    "IsSuperUser",
]
