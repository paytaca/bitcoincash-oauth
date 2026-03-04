"""
Management command to create an OAuth user

Usage:
    python manage.py bitcoincash_create_user <wallet_hash> <address> [--public-key KEY]
"""

from django.core.management.base import BaseCommand, CommandError
from bitcoincash_oauth_django.validator import BitcoinCashValidator
from bitcoincash_oauth_django.settings import get_settings


def _get_user_model():
    """Get the user model class"""
    return get_settings().get_user_model()


class Command(BaseCommand):
    help = "Create a new Bitcoin Cash OAuth user"

    def add_arguments(self, parser):
        parser.add_argument(
            "wallet_hash",
            type=str,
            help="The wallet hash (user_id) for the new user",
        )
        parser.add_argument(
            "address",
            type=str,
            help="The Bitcoin Cash CashAddr address",
        )
        parser.add_argument(
            "--public-key",
            type=str,
            help="Optional public key for the user",
        )
        parser.add_argument(
            "--staff",
            action="store_true",
            help="Grant staff status to the user",
        )
        parser.add_argument(
            "--superuser",
            action="store_true",
            help="Grant superuser status to the user",
        )

    def handle(self, *args, **options):
        wallet_hash = options["wallet_hash"]
        address = options["address"]
        public_key = options.get("public_key")
        is_staff = options.get("staff", False)
        is_superuser = options.get("superuser", False)

        # Validate address format
        is_valid, network = BitcoinCashValidator.validate_cash_address(address)
        if not is_valid:
            raise CommandError(f"Invalid Bitcoin Cash address: {address}")

        # Check if user already exists
        if _get_user_model().objects.filter(user_id=wallet_hash).exists():
            raise CommandError(f'User with wallet hash "{wallet_hash}" already exists')

        if _get_user_model().objects.filter(bitcoincash_address=address).exists():
            raise CommandError(f'User with address "{address}" already exists')

        # Create user
        try:
            user = _get_user_model().objects.create_user(
                user_id=wallet_hash,
                bitcoincash_address=address,
                public_key=public_key or "",
                is_staff=is_staff,
                is_superuser=is_superuser,
            )

            self.stdout.write(
                self.style.SUCCESS(f"Successfully created user: {user.user_id}")
            )
            self.stdout.write(f"  Address: {user.bitcoincash_address}")
            self.stdout.write(f"  Network: {network}")

            if is_staff:
                self.stdout.write(self.style.WARNING("  Staff status: Yes"))
            if is_superuser:
                self.stdout.write(self.style.WARNING("  Superuser status: Yes"))

        except Exception as e:
            raise CommandError(f"Failed to create user: {str(e)}")
