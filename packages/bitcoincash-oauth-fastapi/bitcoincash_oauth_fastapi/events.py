"""
Bitcoin Cash OAuth FastAPI - Events
Webhook-style event system for token lifecycle and authentication events

Usage:
    from bitcoincash_oauth_fastapi import oauth_events

    @oauth_events.on("token_created")
    async def on_token_created(user, token):
        logger.info(f"Token created for {user.user_id}")
        await send_notification(user, "New login detected")
"""

import asyncio
from typing import Callable, List, Dict, Any
from functools import wraps


class EventEmitter:
    """
    Simple event emitter for OAuth lifecycle events

    Events:
        - token_created: Fired when a new token is created
        - token_refreshed: Fired when a token is refreshed
        - token_revoked: Fired when a token is revoked
        - user_registered: Fired when a new user registers
        - user_authenticated: Fired when a user authenticates
        - authentication_failed: Fired when authentication fails
        - registration_failed: Fired when registration fails
    """

    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}

    def on(self, event_name: str):
        """
        Decorator to register an event handler

        Usage:
            @oauth_events.on("token_created")
            async def handler(user, token):
                pass
        """

        def decorator(func: Callable):
            self.add_listener(event_name, func)
            return func

        return decorator

    def add_listener(self, event_name: str, handler: Callable) -> None:
        """Add an event listener"""
        if event_name not in self._handlers:
            self._handlers[event_name] = []
        self._handlers[event_name].append(handler)

    def remove_listener(self, event_name: str, handler: Callable) -> None:
        """Remove an event listener"""
        if event_name in self._handlers:
            self._handlers[event_name] = [
                h for h in self._handlers[event_name] if h != handler
            ]

    async def emit(self, event_name: str, *args, **kwargs) -> None:
        """
        Emit an event to all registered handlers

        Args:
            event_name: Name of the event
            *args: Positional arguments to pass to handlers
            **kwargs: Keyword arguments to pass to handlers
        """
        handlers = self._handlers.get(event_name, [])

        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(*args, **kwargs)
                else:
                    handler(*args, **kwargs)
            except Exception as e:
                # Log error but don't break other handlers
                print(f"[BitcoinCashOAuth] Event handler error for {event_name}: {e}")

    def emit_sync(self, event_name: str, *args, **kwargs) -> None:
        """Synchronous version of emit (for use in sync contexts)"""
        handlers = self._handlers.get(event_name, [])

        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    # Schedule async handler
                    asyncio.create_task(handler(*args, **kwargs))
                else:
                    handler(*args, **kwargs)
            except Exception as e:
                print(f"[BitcoinCashOAuth] Event handler error for {event_name}: {e}")


# Global event emitter instance
oauth_events = EventEmitter()


# Convenience functions for common event patterns


async def emit_token_created(user, token, request=None):
    """Emit token_created event"""
    await oauth_events.emit("token_created", user=user, token=token, request=request)


async def emit_token_refreshed(user, old_token, new_token, request=None):
    """Emit token_refreshed event"""
    await oauth_events.emit(
        "token_refreshed",
        user=user,
        old_token=old_token,
        new_token=new_token,
        request=request,
    )


async def emit_token_revoked(user, token, request=None):
    """Emit token_revoked event"""
    await oauth_events.emit("token_revoked", user=user, token=token, request=request)


async def emit_user_registered(user, request=None):
    """Emit user_registered event"""
    await oauth_events.emit("user_registered", user=user, request=request)


async def emit_user_authenticated(user, token, request=None):
    """Emit user_authenticated event"""
    await oauth_events.emit(
        "user_authenticated", user=user, token=token, request=request
    )


async def emit_authentication_failed(user_id=None, reason=None, request=None):
    """Emit authentication_failed event"""
    await oauth_events.emit(
        "authentication_failed", user_id=user_id, reason=reason, request=request
    )


async def emit_registration_failed(address=None, reason=None, request=None):
    """Emit registration_failed event"""
    await oauth_events.emit(
        "registration_failed", address=address, reason=reason, request=request
    )


# Example usage in documentation
__doc__ += """

Example Usage:
    from bitcoincash_oauth_fastapi import oauth_events
    import logging
    
    logger = logging.getLogger(__name__)
    
    @oauth_events.on("token_created")
    async def log_token_creation(user, token, request):
        logger.info(f"New token created for user {user.user_id}")
        
        # Send security notification
        if request:
            ip = request.client.host
            logger.info(f"Token created from IP: {ip}")
    
    @oauth_events.on("authentication_failed")
    async def log_auth_failure(user_id, reason, request):
        logger.warning(f"Authentication failed for {user_id}: {reason}")
        
        # Could implement rate limiting here
        # Could send security alerts
    
    @oauth_events.on("user_registered")
    async def welcome_new_user(user, request):
        # Send welcome email
        await send_welcome_email(user.bitcoincash_address)
"""
