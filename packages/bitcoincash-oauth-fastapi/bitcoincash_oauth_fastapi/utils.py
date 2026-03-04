"""
Bitcoin Cash OAuth FastAPI - Utilities
Helper functions for common operations
"""

from typing import Optional, List
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .config import get_user_model, get_token_model
from .dependencies import oauth2_scheme


def create_registration_message(
    user_id: str, timestamp: int, domain: str = "oauth"
) -> str:
    """
    Create a registration message to be signed by the client

    This ensures only the wallet owner can register

    Args:
        user_id: The wallet hash
        timestamp: Unix timestamp
        domain: Domain for message binding

    Returns:
        str: The message to sign

    Usage:
        message = create_registration_message(wallet_hash, int(time.time()), 'myapp.com')
        signature = sign_with_wallet(message)  # Client-side
    """
    return f"bitcoincash-oauth|{domain}|{user_id}|{timestamp}|register"


def get_client_ip(request: Request) -> Optional[str]:
    """
    Extract client IP address from request

    Checks X-Forwarded-For header first (for proxies),
    falls back to direct connection

    Args:
        request: FastAPI Request object

    Returns:
        str: IP address or None
    """
    # Check for forwarded IP (behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Get first IP in chain
        return forwarded.split(",")[0].strip()

    # Check for other forwarded headers
    real_ip = request.headers.get("X-Real-Ip")
    if real_ip:
        return real_ip

    # Direct connection
    if request.client:
        return request.client.host

    return None


def get_user_agent(request: Request) -> str:
    """Get user agent from request"""
    return request.headers.get("User-Agent", "")[:255]


async def extract_token_from_request(request: Request) -> Optional[str]:
    """
    Extract Bearer token from request headers

    Args:
        request: FastAPI Request object

    Returns:
        str: Token string or None
    """
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer "

    return None


async def filter_by_owner(query, user_id: str, field_name: str = "user_id"):
    """
    Filter a query by wallet hash

    Args:
        query: SQLAlchemy query
        user_id: The wallet hash to filter by
        field_name: The field name to filter on

    Returns:
        Filtered query

    Usage:
        query = select(Transaction)
        query = await filter_by_owner(query, wallet_hash)
        result = await db.execute(query)
    """
    return query.where(getattr(Transaction, field_name) == user_id)


async def get_user_token_count(
    db: AsyncSession, user_id: str, active_only: bool = True
) -> int:
    """
    Get the number of tokens for a user

    Args:
        db: Database session
        user_id: User ID
        active_only: Only count non-revoked tokens

    Returns:
        int: Token count
    """
    from sqlalchemy import func

    TokenModel = get_token_model()
    query = select(func.count()).where(TokenModel.user_id == user_id)

    if active_only:
        query = query.where(TokenModel.is_revoked == False)

    result = await db.execute(query)
    return result.scalar()


async def cleanup_user_tokens(
    db: AsyncSession, user_id: str, keep_newest: int = 5
) -> int:
    """
    Clean up old tokens for a user, keeping only the newest ones

    Args:
        db: Database session
        user_id: User ID
        keep_newest: Number of newest tokens to keep

    Returns:
        int: Number of tokens revoked
    """
    # Get all tokens ordered by creation date
    TokenModel = get_token_model()
    result = await db.execute(
        select(TokenModel)
        .where(TokenModel.user_id == user_id, TokenModel.is_revoked == False)
        .order_by(TokenModel.created_at.desc())
    )
    tokens = result.scalars().all()

    # Revoke old tokens beyond the limit
    to_revoke = tokens[keep_newest:]
    count = 0
    now = datetime.now(timezone.utc)

    for token in to_revoke:
        token.is_revoked = True
        token.revoked_at = now
        count += 1

    await db.commit()
    return count


class TokenExpiryInfo:
    """
    Helper class to get token expiry information

    Usage:
        expiry_info = TokenExpiryInfo(token)
        if expiry_info.is_about_to_expire:
            print(f"Token expires in {expiry_info.seconds_remaining} seconds")
    """

    def __init__(self, token):
        self.token = token
        self.expires_at = token.expires_at
        self.now = datetime.now(timezone.utc)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return self.now > self.expires_at

    @property
    def seconds_remaining(self) -> int:
        """Get seconds until expiration"""
        if self.is_expired:
            return 0
        remaining = self.expires_at - self.now
        return int(remaining.total_seconds())

    @property
    def is_about_to_expire(self, threshold_seconds: int = 300) -> bool:
        """Check if token expires within threshold (default 5 minutes)"""
        return self.seconds_remaining < threshold_seconds

    @property
    def percent_remaining(self) -> float:
        """Get percentage of token lifetime remaining"""
        from .config import get_settings

        settings = get_settings()

        total_lifetime = settings.ACCESS_TOKEN_LIFETIME
        remaining = self.seconds_remaining

        if remaining <= 0:
            return 0.0

        return (remaining / total_lifetime) * 100


# Pagination helpers


def paginate_query(query, page: int = 1, per_page: int = 20):
    """
    Add pagination to a SQLAlchemy query

    Args:
        query: SQLAlchemy query
        page: Page number (1-indexed)
        per_page: Items per page

    Returns:
        Paginated query
    """
    offset = (page - 1) * per_page
    return query.offset(offset).limit(per_page)


async def get_pagination_info(
    db: AsyncSession, query, page: int = 1, per_page: int = 20
) -> dict:
    """
    Get pagination metadata

    Returns:
        dict with total, pages, page, per_page, has_next, has_prev
    """
    from sqlalchemy import func

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    result = await db.execute(count_query)
    total = result.scalar()

    pages = (total + per_page - 1) // per_page

    return {
        "total": total,
        "pages": pages,
        "page": page,
        "per_page": per_page,
        "has_next": page < pages,
        "has_prev": page > 1,
    }
