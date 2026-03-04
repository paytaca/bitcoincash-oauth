"""
Bitcoin Cash OAuth Django - Signals
Webhook signals for token lifecycle events

Usage:
    from bitcoincash_oauth_django.signals import token_created, token_refreshed, token_revoked

    @receiver(token_created)
    def log_token_creation(sender, user, token, **kwargs):
        logger.info(f"Token created for user {user.user_id}")
"""

from django.dispatch import Signal


# Token lifecycle signals
token_created = Signal()
"""
Sent when a new token pair is created

Provides arguments:
    sender: The class that created the token
    user: The BitcoinCashUser instance
    token: The OAuthToken instance
    request: The Django request object (if available)
"""

token_refreshed = Signal()
"""
Sent when a token is refreshed

Provides arguments:
    sender: The class that refreshed the token
    user: The BitcoinCashUser instance
    old_token: The old OAuthToken instance
    new_token: The new OAuthToken instance
    request: The Django request object (if available)
"""

token_revoked = Signal()
"""
Sent when a token is revoked

Provides arguments:
    sender: The class that revoked the token
    user: The BitcoinCashUser instance
    token: The OAuthToken instance
    request: The Django request object (if available)
"""

user_registered = Signal()
"""
Sent when a new user is registered

Provides arguments:
    sender: The class that registered the user
    user: The BitcoinCashUser instance
    request: The Django request object (if available)
"""

user_authenticated = Signal()
"""
Sent when a user is successfully authenticated

Provides arguments:
    sender: The class that authenticated the user
    user: The BitcoinCashUser instance
    token: The OAuthToken instance
    request: The Django request object (if available)
"""

authentication_failed = Signal()
"""
Sent when authentication fails

Provides arguments:
    sender: The class that attempted authentication
    user_id: The user_id that was attempted (may be None)
    reason: The reason for failure
    request: The Django request object (if available)
"""

registration_failed = Signal()
"""
Sent when registration fails

Provides arguments:
    sender: The class that attempted registration
    address: The address that was attempted
    reason: The reason for failure
    request: The Django request object (if available)
"""
