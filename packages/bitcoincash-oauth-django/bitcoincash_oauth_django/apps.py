"""
Bitcoin Cash OAuth Django - App Configuration
"""

from django.apps import AppConfig


class BitcoinCashOAuthConfig(AppConfig):
    """Django app configuration for Bitcoin Cash OAuth"""

    default_auto_field = "django.db.models.BigAutoField"
    name = "bitcoincash_oauth_django"
    verbose_name = "Bitcoin Cash OAuth"

    def ready(self):
        """App initialization"""
        # Import signal handlers
        from . import signals

        # Validate settings
        from .settings import check_settings

        try:
            check_settings()
        except Exception:
            # Settings validation will run again when Django is fully configured
            pass
