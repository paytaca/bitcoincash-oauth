"""
Bitcoin Cash OAuth Django - Settings
Configuration and settings management
"""

from datetime import timedelta
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


DEFAULTS = {
    # Token lifetimes
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    # Token settings
    "MAX_TOKENS_PER_USER": 5,
    "TOKEN_CLEANUP_DAYS": 7,  # Delete expired tokens after this many days
    # Authentication settings
    "MAX_TIMESTAMP_DIFF": 300,  # 5 minutes - max time difference for timestamp validation
    "DEFAULT_SCOPES": ["read"],
    # Network settings
    "NETWORK": "mainnet",  # or 'testnet'
    # Registration settings
    "REQUIRE_SIGNATURE_FOR_REGISTRATION": True,  # Security: require signature to prove ownership
    # Rate limiting (optional)
    "RATE_LIMIT": {
        "token_endpoint": "5/m",  # 5 per minute
        "refresh_endpoint": "10/m",
        "register_endpoint": "3/m",
    },
    # User model
    "USER_MODEL": None,  # Set to use a custom user model, e.g., 'myapp.MyUser'
}


class OAuthSettings:
    """
    Settings wrapper for Bitcoin Cash OAuth Django

    Reads from Django settings.BITCOINCASH_OAUTH dict
    """

    def __init__(self):
        self._settings = getattr(settings, "BITCOINCASH_OAUTH", {})

    def __getattr__(self, name):
        """Get a setting value, falling back to defaults"""
        if name not in DEFAULTS:
            raise AttributeError(
                f"'{self.__class__.__name__}' has no attribute '{name}'"
            )

        return self._settings.get(name, DEFAULTS[name])

    @property
    def access_token_lifetime(self):
        """Get access token lifetime in seconds"""
        lifetime = self.ACCESS_TOKEN_LIFETIME
        if isinstance(lifetime, timedelta):
            return int(lifetime.total_seconds())
        return int(lifetime)

    @property
    def refresh_token_lifetime(self):
        """Get refresh token lifetime in seconds"""
        lifetime = self.REFRESH_TOKEN_LIFETIME
        if isinstance(lifetime, timedelta):
            return int(lifetime.total_seconds())
        return int(lifetime)

    def get_user_model_string(self):
        """Get the user model string from settings or use default"""
        if self.USER_MODEL:
            return self.USER_MODEL
        return "bitcoincash_oauth_django.BitcoinCashUser"

    def get_user_model(self):
        """Get the user model class"""
        from django.apps import apps

        model_string = self.get_user_model_string()
        return apps.get_model(model_string)


# Singleton instance
_oauth_settings = None


def get_settings():
    """Get the OAuth settings singleton"""
    global _oauth_settings
    if _oauth_settings is None:
        _oauth_settings = OAuthSettings()
    return _oauth_settings


def reload_settings():
    """Reload settings (useful for testing)"""
    global _oauth_settings
    _oauth_settings = OAuthSettings()


def check_settings():
    """Validate settings configuration"""
    oauth_settings = get_settings()

    # Check that required Django apps are installed
    required_apps = [
        "django.contrib.auth",
        "django.contrib.contenttypes",
    ]

    for app in required_apps:
        if app not in settings.INSTALLED_APPS:
            raise ImproperlyConfigured(
                f"'{app}' must be in INSTALLED_APPS to use bitcoincash-oauth-django"
            )

    # Validate network setting
    valid_networks = ["mainnet", "testnet", "regtest"]
    if oauth_settings.NETWORK not in valid_networks:
        raise ImproperlyConfigured(
            f"BITCOINCASH_OAUTH['NETWORK'] must be one of {valid_networks}"
        )

    # Validate token lifetimes
    if oauth_settings.access_token_lifetime <= 0:
        raise ImproperlyConfigured(
            "BITCOINCASH_OAUTH['ACCESS_TOKEN_LIFETIME'] must be positive"
        )

    if oauth_settings.refresh_token_lifetime <= 0:
        raise ImproperlyConfigured(
            "BITCOINCASH_OAUTH['REFRESH_TOKEN_LIFETIME'] must be positive"
        )

    return True
