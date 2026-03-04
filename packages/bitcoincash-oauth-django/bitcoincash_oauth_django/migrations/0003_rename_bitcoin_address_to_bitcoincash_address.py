# Generated manually - Rename bitcoin_address to bitcoincash_address for consistency

from django.db import migrations


class Migration(migrations.Migration):
    """Rename bitcoin_address field to bitcoincash_address for naming consistency"""

    dependencies = [
        (
            "bitcoincash_oauth_django",
            "0002_rename_bitcoincash_user_revok_1f8f66_idx_bitcoincash_user_id_950995_idx_and_more",
        ),
    ]

    operations = [
        migrations.RenameField(
            model_name="bitcoincashuser",
            old_name="bitcoin_address",
            new_name="bitcoincash_address",
        ),
    ]
