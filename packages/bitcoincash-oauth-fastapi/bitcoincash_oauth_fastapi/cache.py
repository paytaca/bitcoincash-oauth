"""
Bitcoin Cash OAuth FastAPI - Cache
Cache management for token blacklisting and other features
"""

import asyncio
from typing import Optional
from datetime import timedelta

try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .config import get_settings


class CacheManager:
    """
    Manages caching for token blacklisting and other features

    Supports Redis if available, falls back to in-memory dict
    """

    def __init__(self):
        self._redis: Optional[redis.Redis] = None
        self._memory_cache: dict = {}
        self._initialized = False

    async def init(self) -> None:
        """Initialize cache connection"""
        settings = get_settings()

        if settings.REDIS_URL and REDIS_AVAILABLE:
            try:
                self._redis = await redis.from_url(
                    settings.REDIS_URL, encoding="utf-8", decode_responses=True
                )
                await self._redis.ping()
                self._initialized = True
                print("[BitcoinCashOAuth] Redis cache initialized")
            except Exception as e:
                print(
                    f"[BitcoinCashOAuth] Redis connection failed: {e}, using memory cache"
                )
                self._redis = None
        else:
            if settings.REDIS_URL and not REDIS_AVAILABLE:
                print(
                    "[BitcoinCashOAuth] Redis URL set but redis not installed, using memory cache"
                )
            self._redis = None

        self._initialized = True

    async def close(self) -> None:
        """Close cache connection"""
        if self._redis:
            await self._redis.close()
        self._initialized = False

    def _make_key(self, key: str) -> str:
        """Add prefix to key"""
        settings = get_settings()
        return f"{settings.CACHE_PREFIX}:{key}"

    async def set(self, key: str, value: any, expire: int = None) -> None:
        """
        Set a value in cache

        Args:
            key: Cache key
            value: Value to store
            expire: Expiration time in seconds
        """
        if not self._initialized:
            await self.init()

        full_key = self._make_key(key)

        if self._redis:
            if expire:
                await self._redis.setex(full_key, expire, str(value))
            else:
                await self._redis.set(full_key, str(value))
        else:
            # In-memory cache
            self._memory_cache[full_key] = {
                "value": value,
                "expires": None,  # Simple implementation - no expiration for memory cache
            }

    async def get(self, key: str) -> Optional[any]:
        """
        Get a value from cache

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        if not self._initialized:
            await self.init()

        full_key = self._make_key(key)

        if self._redis:
            value = await self._redis.get(full_key)
            return value
        else:
            # In-memory cache
            item = self._memory_cache.get(full_key)
            if item:
                return item["value"]
            return None

    async def delete(self, key: str) -> None:
        """Delete a key from cache"""
        if not self._initialized:
            await self.init()

        full_key = self._make_key(key)

        if self._redis:
            await self._redis.delete(full_key)
        else:
            self._memory_cache.pop(full_key, None)

    async def exists(self, key: str) -> bool:
        """Check if a key exists in cache"""
        if not self._initialized:
            await self.init()

        full_key = self._make_key(key)

        if self._redis:
            return await self._redis.exists(full_key) > 0
        else:
            return full_key in self._memory_cache

    # Token blacklist specific methods

    async def blacklist_token(self, token: str, expire_seconds: int = None) -> None:
        """
        Add a token to the blacklist

        Args:
            token: The token to blacklist
            expire_seconds: How long to keep in blacklist (defaults to 24 hours)
        """
        if expire_seconds is None:
            expire_seconds = 86400  # 24 hours default

        key = f"blacklist:{token[:32]}"  # Use hash of token for key
        await self.set(key, "1", expire_seconds)

    async def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted"""
        key = f"blacklist:{token[:32]}"
        return await self.exists(key)

    async def clear_memory_cache(self) -> None:
        """Clear in-memory cache (for testing)"""
        self._memory_cache.clear()


# Global instance
cache_manager = CacheManager()
