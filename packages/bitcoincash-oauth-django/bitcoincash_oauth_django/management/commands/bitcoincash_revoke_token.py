"""
Management command to revoke an OAuth token

Usage:
    python manage.py bitcoincash_revoke_token <token>
    python manage.py bitcoincash_revoke_token --user <wallet_hash>
"""

from django.core.management.base import BaseCommand, CommandError
from bitcoincash_oauth_django.settings import get_settings


def _get_user_model():
    """Get the user model class"""
    return get_settings().get_user_model()


def _get_token_model():
    """Get the token model class"""
    return get_settings().get_token_model()


class Command(BaseCommand):
    help = "Revoke an OAuth access token or all tokens for a user"

    def add_arguments(self, parser):
        parser.add_argument(
            "token",
            type=str,
            nargs="?",
            help="The access token to revoke",
        )
        parser.add_argument(
            "--user",
            type=str,
            help="Revoke all tokens for a specific user (wallet hash)",
        )
        parser.add_argument(
            "--all-expired",
            action="store_true",
            help="Revoke all expired tokens",
        )

    def handle(self, *args, **options):
        token = options.get("token")
        wallet_hash = options.get("user")
        all_expired = options.get("all_expired")

        if not any([token, wallet_hash, all_expired]):
            raise CommandError(
                "Please provide a token, --user wallet_hash, or --all-expired"
            )

        # Revoke specific token
        if token:
            oauth_token = _get_token_model().validate_access_token(token)

            if oauth_token is None:
                # Try to find it anyway (might be expired)
                try:
                    oauth_token = _get_token_model().objects.get(access_token=token)
                except _get_token_model().DoesNotExist:
                    raise CommandError(f"Token not found: {token}")

            oauth_token.revoke()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully revoked token for user: {oauth_token.user.user_id}"
                )
            )
            return

        # Revoke all tokens for a user
        if wallet_hash:
            try:
                user = _get_user_model().objects.get(user_id=wallet_hash)
            except _get_user_model().DoesNotExist:
                raise CommandError(f"User not found: {wallet_hash}")

            count = _get_token_model().revoke_all_user_tokens(user)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully revoked {count} tokens for user: {wallet_hash}"
                )
            )
            return

        # Revoke all expired tokens
        if all_expired:
            from django.utils import timezone

            expired_tokens = _get_token_model().objects.filter(
                expires_at__lt=timezone.now(), is_revoked=False
            )

            count = 0
            for token in expired_tokens:
                token.revoke()
                count += 1

            self.stdout.write(
                self.style.SUCCESS(f"Successfully revoked {count} expired tokens")
            )
            return
