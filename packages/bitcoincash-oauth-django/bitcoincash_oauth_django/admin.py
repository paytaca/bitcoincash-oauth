"""
Bitcoin Cash OAuth Django - Admin
Django admin integration for managing users and tokens

Usage:
    from django.contrib import admin
    from bitcoincash_oauth_django.admin import BitcoinCashUserAdmin, OAuthTokenAdmin
    from bitcoincash_oauth_django.models import BitcoinCashUser, OAuthToken

    admin.site.register(BitcoinCashUser, BitcoinCashUserAdmin)
    admin.site.register(OAuthToken, OAuthTokenAdmin)
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from datetime import timedelta

from .models import BitcoinCashUser, OAuthToken


@admin.register(BitcoinCashUser)
class BitcoinCashUserAdmin(admin.ModelAdmin):
    """Admin interface for Bitcoin Cash OAuth users"""

    list_display = [
        "user_id",
        "bitcoin_address",
        "is_active",
        "is_staff",
        "date_joined",
        "last_login",
        "token_count",
    ]

    list_filter = [
        "is_active",
        "is_staff",
        "date_joined",
        "last_login",
    ]

    search_fields = [
        "user_id",
        "bitcoin_address",
        "public_key",
    ]

    readonly_fields = [
        "user_id",
        "date_joined",
        "last_login",
    ]

    fieldsets = (
        ("User Information", {"fields": ("user_id", "bitcoin_address", "public_key")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (
            "Important Dates",
            {
                "fields": ("date_joined", "last_login"),
            },
        ),
    )

    def token_count(self, obj):
        """Display the number of active tokens for this user"""
        count = obj.tokens.filter(is_revoked=False).count()
        return format_html(
            '<span style="color: {};">{} active</span>',
            "green" if count > 0 else "gray",
            count,
        )

    token_count.short_description = "Active Tokens"

    actions = ["revoke_all_tokens", "deactivate_users", "activate_users"]

    def revoke_all_tokens(self, request, queryset):
        """Admin action to revoke all tokens for selected users"""
        total_revoked = 0
        for user in queryset:
            count = OAuthToken.revoke_all_user_tokens(user)
            total_revoked += count

        self.message_user(
            request,
            f"Successfully revoked {total_revoked} tokens for {queryset.count()} users",
        )

    revoke_all_tokens.short_description = "Revoke all tokens for selected users"

    def deactivate_users(self, request, queryset):
        """Admin action to deactivate selected users"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Successfully deactivated {updated} users")

    deactivate_users.short_description = "Deactivate selected users"

    def activate_users(self, request, queryset):
        """Admin action to activate selected users"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"Successfully activated {updated} users")

    activate_users.short_description = "Activate selected users"


@admin.register(OAuthToken)
class OAuthTokenAdmin(admin.ModelAdmin):
    """Admin interface for OAuth tokens"""

    list_display = [
        "id",
        "user_link",
        "token_preview",
        "token_type",
        "status",
        "scopes_display",
        "created_at",
        "expires_at",
    ]

    list_filter = [
        "is_revoked",
        "token_type",
        "created_at",
        "expires_at",
    ]

    search_fields = [
        "user__user_id",
        "user__bitcoin_address",
        "access_token",
        "refresh_token",
    ]

    readonly_fields = [
        "id",
        "access_token",
        "refresh_token",
        "created_at",
        "expires_at",
        "refresh_expires_at",
    ]

    fieldsets = (
        ("Token Information", {"fields": ("id", "user", "token_type", "scopes")}),
        (
            "Tokens",
            {
                "fields": ("access_token", "refresh_token"),
                "classes": ("collapse",),
            },
        ),
        (
            "Status",
            {
                "fields": ("is_revoked", "revoked_at"),
            },
        ),
        (
            "Timestamps",
            {
                "fields": ("created_at", "expires_at", "refresh_expires_at"),
            },
        ),
        (
            "Request Info",
            {
                "fields": ("ip_address", "user_agent"),
                "classes": ("collapse",),
            },
        ),
    )

    def user_link(self, obj):
        """Display user as a link to the user admin"""
        from django.urls import reverse

        url = reverse(
            "admin:bitcoincash_oauth_django_bitcoincashuser_change", args=[obj.user.pk]
        )
        return format_html('<a href="{}">{}</a>', url, obj.user.user_id)

    user_link.short_description = "User"
    user_link.admin_order_field = "user__user_id"

    def token_preview(self, obj):
        """Display a shortened version of the token"""
        return f"{obj.access_token[:20]}..."

    token_preview.short_description = "Access Token"

    def status(self, obj):
        """Display token status with color coding"""
        if obj.is_revoked:
            return format_html('<span style="color: red;">Revoked</span>')
        elif obj.is_expired:
            return format_html('<span style="color: orange;">Expired</span>')
        else:
            return format_html('<span style="color: green;">Active</span>')

    status.short_description = "Status"

    def scopes_display(self, obj):
        """Display scopes as badges"""
        if not obj.scopes:
            return "-"

        badges = []
        for scope in obj.scopes:
            color = "blue"
            if scope == "admin":
                color = "red"
            elif scope == "write":
                color = "orange"
            badges.append(
                f'<span style="background: {color}; color: white; padding: 2px 6px; border-radius: 3px; margin-right: 4px;">{scope}</span>'
            )

        return format_html("".join(badges))

    scopes_display.short_description = "Scopes"

    actions = ["revoke_tokens", "cleanup_expired"]

    def revoke_tokens(self, request, queryset):
        """Admin action to revoke selected tokens"""
        count = 0
        for token in queryset.filter(is_revoked=False):
            token.revoke()
            count += 1

        self.message_user(request, f"Successfully revoked {count} tokens")

    revoke_tokens.short_description = "Revoke selected tokens"

    def cleanup_expired(self, request, queryset):
        """Admin action to clean up expired and revoked tokens"""
        deleted = OAuthToken.cleanup_expired_tokens()
        self.message_user(
            request, f"Successfully cleaned up {deleted} expired/revoked tokens"
        )

    cleanup_expired.short_description = "Clean up expired tokens (global)"

    def has_add_permission(self, request):
        """Disable manual token creation"""
        return False
