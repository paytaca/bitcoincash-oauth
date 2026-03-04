"""
Bitcoin Cash OAuth Django - Models
Django ORM models for database persistence
"""

import uuid
import secrets
from datetime import datetime, timedelta
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)


class BitcoinCashUserManager(BaseUserManager):
    """Custom user manager for Bitcoin Cash OAuth users"""

    def create_user(self, user_id, bitcoin_address, **extra_fields):
        """Create and save a user with the given user_id and bitcoin_address"""
        if not user_id:
            raise ValueError("The user_id must be set")
        if not bitcoin_address:
            raise ValueError("The bitcoin_address must be set")

        user = self.model(
            user_id=user_id, bitcoin_address=bitcoin_address, **extra_fields
        )
        user.set_unusable_password()  # OAuth users don't use passwords
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, bitcoin_address, **extra_fields):
        """Create and save a superuser"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(user_id, bitcoin_address, **extra_fields)


class BitcoinCashUser(AbstractBaseUser, PermissionsMixin):
    """
    Bitcoin Cash OAuth User model

    Uses wallet_hash (user_id) as the primary identifier
    """

    # Primary identifier - wallet hash
    user_id = models.CharField(
        max_length=255,
        unique=True,
        primary_key=True,
        help_text="Wallet hash or user-provided ID",
        db_index=True,
    )

    # Bitcoin Cash address
    bitcoin_address = models.CharField(
        max_length=100,
        unique=True,
        help_text="Bitcoin Cash CashAddr address",
    )

    # User metadata
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)

    # OAuth specific fields
    public_key = models.CharField(
        max_length=132,
        blank=True,
        help_text="Optional: Store user's public key for verification",
    )

    # Django auth configuration
    USERNAME_FIELD = "user_id"
    REQUIRED_FIELDS = ["bitcoin_address"]

    objects = BitcoinCashUserManager()

    class Meta:
        verbose_name = "Bitcoin Cash User"
        verbose_name_plural = "Bitcoin Cash Users"
        db_table = "bitcoincash_oauth_user"
        ordering = ["-date_joined"]

    def __str__(self):
        return f"{self.user_id} ({self.bitcoin_address})"

    def get_full_name(self):
        return self.user_id

    def get_short_name(self):
        return self.user_id

    @property
    def wallet_hash(self):
        """Alias for user_id for convenience"""
        return self.user_id


class OAuthToken(models.Model):
    """
    OAuth Token model for database storage

    Stores access and refresh tokens with expiration tracking
    """

    # Token identifiers
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_token = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="The access token",
    )
    refresh_token = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="The refresh token",
    )

    # Token metadata
    token_type = models.CharField(max_length=20, default="bearer")
    scopes = models.JSONField(default=list, help_text="List of OAuth scopes")

    # User relationship
    user = models.ForeignKey(
        BitcoinCashUser,
        on_delete=models.CASCADE,
        related_name="tokens",
        help_text="The user this token belongs to",
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField()

    # Status
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    # Device/IP tracking (optional)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        verbose_name = "OAuth Token"
        verbose_name_plural = "OAuth Tokens"
        db_table = "bitcoincash_oauth_token"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "is_revoked", "expires_at"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"Token for {self.user.user_id} (expires: {self.expires_at})"

    @property
    def is_expired(self):
        """Check if the access token is expired"""
        return timezone.now() > self.expires_at

    @property
    def is_refresh_expired(self):
        """Check if the refresh token is expired"""
        return timezone.now() > self.refresh_expires_at

    @property
    def expires_in(self):
        """Calculate seconds until expiration"""
        if self.is_expired:
            return 0
        return int((self.expires_at - timezone.now()).total_seconds())

    def revoke(self):
        """Revoke this token"""
        self.is_revoked = True
        self.revoked_at = timezone.now()
        self.save(update_fields=["is_revoked", "revoked_at"])

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scopes": self.scopes,
            "user_id": self.user.user_id,
        }

    @classmethod
    def generate_token(cls):
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(32)

    @classmethod
    def create_token_pair(cls, user, scopes=None, ip_address=None, user_agent=""):
        """Create a new access/refresh token pair for a user"""
        from .settings import get_settings

        settings = get_settings()
        now = timezone.now()

        access_token = cls.generate_token()
        refresh_token = cls.generate_token()

        token = cls.objects.create(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token,
            scopes=scopes or ["read"],
            expires_at=now + timedelta(seconds=settings.access_token_lifetime),
            refresh_expires_at=now + timedelta(seconds=settings.refresh_token_lifetime),
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else "",
        )

        return token

    @classmethod
    def validate_access_token(cls, access_token):
        """
        Validate an access token and return the token object

        Checks:
        - Token exists in database
        - Token is not revoked
        - Token is not expired
        - Token is not in the blacklist (cache)
        """
        # Check blacklist first (fast cache lookup)
        from django.core.cache import cache

        blacklist_key = f"bitcoincash_token_blacklist_{access_token[:32]}"
        if cache.get(blacklist_key):
            return None

        try:
            token = cls.objects.select_related("user").get(
                access_token=access_token,
                is_revoked=False,
            )

            if token.is_expired:
                return None

            return token
        except cls.DoesNotExist:
            return None

    @classmethod
    def validate_refresh_token(cls, refresh_token):
        """
        Validate a refresh token and return the token object

        Checks:
        - Token exists in database
        - Token is not revoked
        - Token is not expired
        - Token is not in the blacklist (cache)
        """
        # Check blacklist first
        from django.core.cache import cache

        blacklist_key = f"bitcoincash_token_blacklist_{refresh_token[:32]}"
        if cache.get(blacklist_key):
            return None

        try:
            token = cls.objects.select_related("user").get(
                refresh_token=refresh_token,
                is_revoked=False,
            )

            if token.is_refresh_expired:
                return None

            return token
        except cls.DoesNotExist:
            return None

    @classmethod
    def revoke_all_user_tokens(cls, user):
        """Revoke all tokens for a user"""
        return cls.objects.filter(user=user, is_revoked=False).update(
            is_revoked=True, revoked_at=timezone.now()
        )

    @classmethod
    def cleanup_expired_tokens(cls):
        """Delete expired and revoked tokens older than a threshold"""
        from .settings import get_settings

        settings = get_settings()
        threshold = timezone.now() - timedelta(days=settings.token_cleanup_days)

        deleted, _ = cls.objects.filter(
            models.Q(is_revoked=True, revoked_at__lt=threshold)
            | models.Q(expires_at__lt=threshold)
        ).delete()

        return deleted
