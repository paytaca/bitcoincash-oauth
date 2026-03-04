"""
Management command to clean up expired and revoked tokens

Usage:
    python manage.py bitcoincash_cleanup_tokens [--dry-run]
"""

from django.core.management.base import BaseCommand
from bitcoincash_oauth_django.settings import get_settings


def _get_token_model():
    """Get the token model class"""
    return get_settings().get_token_model()


class Command(BaseCommand):
    help = "Clean up expired and revoked OAuth tokens from the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without actually deleting",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN - No deletions will be made"))

        # Get count before cleanup
        total_tokens = _get_token_model().objects.count()

        # Cleanup expired tokens
        deleted = _get_token_model().cleanup_expired_tokens()

        remaining = _get_token_model().objects.count()

        self.stdout.write(
            self.style.SUCCESS(
                f"Cleanup complete: {deleted} tokens deleted, {remaining} tokens remaining"
            )
        )

        if not dry_run and deleted > 0:
            self.stdout.write(
                self.style.HTTP_INFO(
                    f"Reduced token count from {total_tokens} to {remaining}"
                )
            )
