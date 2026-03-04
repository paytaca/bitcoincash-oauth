# Generated manually for Bitcoin Cash OAuth Django v2.0.0

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):
    """Initial migration for Bitcoin Cash OAuth Django models"""

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="BitcoinCashUser",
            fields=[
                (
                    "user_id",
                    models.CharField(
                        max_length=255,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                        help_text="Wallet hash or user-provided ID",
                        db_index=True,
                    ),
                ),
                (
                    "bitcoin_address",
                    models.CharField(
                        max_length=100,
                        unique=True,
                        help_text="Bitcoin Cash CashAddr address",
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False)),
                (
                    "date_joined",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                ("last_login", models.DateTimeField(blank=True, null=True)),
                (
                    "public_key",
                    models.CharField(
                        blank=True,
                        max_length=132,
                        help_text="Optional: Store user's public key for verification",
                    ),
                ),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to.",
                        related_name="bitcoincash_user_set",
                        related_query_name="bitcoincash_user",
                        to="auth.group",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="bitcoincash_user_set",
                        related_query_name="bitcoincash_user",
                        to="auth.permission",
                    ),
                ),
            ],
            options={
                "verbose_name": "Bitcoin Cash User",
                "verbose_name_plural": "Bitcoin Cash Users",
                "db_table": "bitcoincash_oauth_user",
                "ordering": ["-date_joined"],
            },
        ),
        migrations.CreateModel(
            name="OAuthToken",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "access_token",
                    models.CharField(
                        db_index=True,
                        max_length=255,
                        unique=True,
                        help_text="The access token",
                    ),
                ),
                (
                    "refresh_token",
                    models.CharField(
                        db_index=True,
                        max_length=255,
                        unique=True,
                        help_text="The refresh token",
                    ),
                ),
                ("token_type", models.CharField(default="bearer", max_length=20)),
                (
                    "scopes",
                    models.JSONField(
                        default=list,
                        help_text="List of OAuth scopes",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField()),
                ("refresh_expires_at", models.DateTimeField()),
                ("is_revoked", models.BooleanField(default=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True)),
                (
                    "user",
                    models.ForeignKey(
                        help_text="The user this token belongs to",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tokens",
                        to="bitcoincash_oauth_django.bitcoincashuser",
                    ),
                ),
            ],
            options={
                "verbose_name": "OAuth Token",
                "verbose_name_plural": "OAuth Tokens",
                "db_table": "bitcoincash_oauth_token",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="oauthtoken",
            index=models.Index(
                fields=["user", "is_revoked", "expires_at"],
                name="bitcoincash_user_revok_1f8f66_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="oauthtoken",
            index=models.Index(
                fields=["created_at"],
                name="bitcoincash_created_3c9f6b_idx",
            ),
        ),
    ]
