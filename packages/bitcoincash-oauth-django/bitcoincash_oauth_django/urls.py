"""
Bitcoin Cash OAuth Django - URL Configuration

Usage:
    from django.urls import path, include

    urlpatterns = [
        path('auth/', include('bitcoincash_oauth_django.urls')),
    ]
"""

from django.urls import path
from . import drf_views


app_name = "bitcoincash_oauth"

urlpatterns = [
    # Registration
    path("register", drf_views.RegisterView.as_view(), name="register"),
    path("register/", drf_views.RegisterView.as_view(), name="register-slash"),
    # Token endpoints
    path("token", drf_views.TokenView.as_view(), name="token"),
    path("token/", drf_views.TokenView.as_view(), name="token-slash"),
    # Refresh
    path("refresh", drf_views.RefreshView.as_view(), name="refresh"),
    path("refresh/", drf_views.RefreshView.as_view(), name="refresh-slash"),
    # Revoke
    path("revoke", drf_views.RevokeView.as_view(), name="revoke"),
    path("revoke/", drf_views.RevokeView.as_view(), name="revoke-slash"),
    # User info
    path("me", drf_views.MeView.as_view(), name="me"),
    path("me/", drf_views.MeView.as_view(), name="me-slash"),
]
