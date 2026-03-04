"""
Bitcoin Cash OAuth FastAPI - Database Models
SQLAlchemy async models for database persistence
"""

import uuid
import secrets
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, DateTime, ForeignKey, JSON, Index, select, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings


class Base(DeclarativeBase):
    """Base class for all models"""

    pass


class BitcoinCashUser(Base):
    """
    Bitcoin Cash OAuth User model

    Uses wallet_hash (user_id) as the primary identifier
    """

    __tablename__ = "bitcoincash_oauth_users"

    user_id: Mapped[str] = mapped_column(
        String(255),
        primary_key=True,
        index=True,
        comment="Wallet hash or user-provided ID",
    )
    bitcoin_address: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, comment="Bitcoin Cash CashAddr address"
    )
    public_key: Mapped[Optional[str]] = mapped_column(
        String(132),
        nullable=True,
        comment="Optional: User's public key for verification",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, comment="Whether the user is active"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), comment="When the user was created"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=func.now(),
        onupdate=func.now(),
        comment="When the user was last updated",
    )

    # Relationships
    tokens: Mapped[List["OAuthToken"]] = relationship(
        "OAuthToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<BitcoinCashUser(user_id={self.user_id}, address={self.bitcoin_address})>"
        )

    @property
    def wallet_hash(self) -> str:
        """Alias for user_id"""
        return self.user_id


class OAuthToken(Base):
    """
    OAuth Token model for database storage

    Stores access and refresh tokens with expiration tracking
    """

    __tablename__ = "bitcoincash_oauth_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True)
        if False
        else String(36),  # Use String for SQLite compatibility
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique token ID",
    )
    access_token: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, comment="The access token"
    )
    refresh_token: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, comment="The refresh token"
    )
    token_type: Mapped[str] = mapped_column(
        String(20), default="bearer", comment="Token type (usually 'bearer')"
    )
    scopes: Mapped[List[str]] = mapped_column(
        JSON, default=list, comment="List of OAuth scopes"
    )

    # Foreign key to user
    user_id: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("bitcoincash_oauth_users.user_id", ondelete="CASCADE"),
        index=True,
        comment="The user this token belongs to",
    )
    user: Mapped["BitcoinCashUser"] = relationship(
        "BitcoinCashUser", back_populates="tokens"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=func.now(),
        comment="When the token was created",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), comment="When the access token expires"
    )
    refresh_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), comment="When the refresh token expires"
    )

    # Status
    is_revoked: Mapped[bool] = mapped_column(
        Boolean, default=False, comment="Whether the token has been revoked"
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="When the token was revoked"
    )

    # Request tracking
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="IP address of the request that created this token",
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="User agent of the request that created this token",
    )

    # Table indexes
    __table_args__ = (
        Index("idx_tokens_user_active", "user_id", "is_revoked", "expires_at"),
        Index("idx_tokens_created", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<OAuthToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"

    @property
    def is_expired(self) -> bool:
        """Check if the access token is expired"""
        return datetime.now(self.expires_at.tzinfo) > self.expires_at

    @property
    def is_refresh_expired(self) -> bool:
        """Check if the refresh token is expired"""
        return datetime.now(self.refresh_expires_at.tzinfo) > self.refresh_expires_at

    @property
    def expires_in(self) -> int:
        """Calculate seconds until expiration"""
        if self.is_expired:
            return 0
        remaining = self.expires_at - datetime.now(self.expires_at.tzinfo)
        return int(remaining.total_seconds())

    async def revoke(self, db: AsyncSession) -> None:
        """Revoke this token"""
        from datetime import timezone

        self.is_revoked = True
        self.revoked_at = datetime.now(timezone.utc)
        await db.commit()

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scopes": self.scopes,
            "user_id": self.user_id,
        }

    @staticmethod
    def generate_token() -> str:
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(32)

    @classmethod
    async def create_token_pair(
        cls,
        db: AsyncSession,
        user: BitcoinCashUser,
        scopes: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "OAuthToken":
        """Create a new access/refresh token pair for a user"""
        from datetime import timedelta, timezone

        settings = get_settings()
        now = datetime.now(timezone.utc)

        access_token = cls.generate_token()
        refresh_token = cls.generate_token()

        token = cls(
            user_id=user.user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            scopes=scopes or settings.DEFAULT_SCOPES,
            expires_at=now + timedelta(seconds=settings.ACCESS_TOKEN_LIFETIME),
            refresh_expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_LIFETIME),
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else None,
        )

        db.add(token)
        await db.commit()
        await db.refresh(token)

        return token

    @classmethod
    async def validate_access_token(
        cls, db: AsyncSession, access_token: str
    ) -> Optional["OAuthToken"]:
        """Validate an access token and return the token object"""
        result = await db.execute(
            select(cls)
            .where(cls.access_token == access_token, cls.is_revoked == False)
            .options(relationship(cls.user))
        )
        token = result.scalar_one_or_none()

        if token is None:
            return None

        if token.is_expired:
            return None

        return token

    @classmethod
    async def validate_refresh_token(
        cls, db: AsyncSession, refresh_token: str
    ) -> Optional["OAuthToken"]:
        """Validate a refresh token and return the token object"""
        result = await db.execute(
            select(cls)
            .where(cls.refresh_token == refresh_token, cls.is_revoked == False)
            .options(relationship(cls.user))
        )
        token = result.scalar_one_or_none()

        if token is None:
            return None

        if token.is_refresh_expired:
            return None

        return token

    @classmethod
    async def revoke_all_user_tokens(cls, db: AsyncSession, user_id: str) -> int:
        """Revoke all tokens for a user"""
        from datetime import timezone

        result = await db.execute(
            select(cls).where(cls.user_id == user_id, cls.is_revoked == False)
        )
        tokens = result.scalars().all()

        count = 0
        now = datetime.now(timezone.utc)
        for token in tokens:
            token.is_revoked = True
            token.revoked_at = now
            count += 1

        await db.commit()
        return count

    @classmethod
    async def cleanup_expired_tokens(cls, db: AsyncSession) -> int:
        """Delete expired and revoked tokens older than a threshold"""
        from datetime import timedelta, timezone

        settings = get_settings()
        threshold = datetime.now(timezone.utc) - timedelta(
            days=settings.TOKEN_CLEANUP_DAYS
        )

        result = await db.execute(
            select(cls).where(
                (cls.is_revoked == True) & (cls.revoked_at < threshold)
                | (cls.expires_at < threshold)
            )
        )
        tokens_to_delete = result.scalars().all()

        count = len(tokens_to_delete)
        for token in tokens_to_delete:
            await db.delete(token)

        await db.commit()
        return count
