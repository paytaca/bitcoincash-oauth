"""
Bitcoin Cash OAuth FastAPI - Database Connection
Async database session management using SQLAlchemy
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool

from .config import get_settings
from .models import Base


class DatabaseManager:
    """
    Manages async database connections and sessions

    Usage:
        # Initialize on app startup
        db_manager = DatabaseManager()
        await db_manager.init_db()

        # Get session dependency
        async with db_manager.get_session() as session:
            user = await session.get(BitcoinCashUser, user_id)
    """

    def __init__(self):
        self.engine: AsyncEngine = None
        self.session_maker = None
        self._initialized = False

    def init_engine(self) -> AsyncEngine:
        """Initialize the database engine"""
        settings = get_settings()

        # SQLite needs different pool configuration
        if "sqlite" in settings.DATABASE_URL:
            engine = create_async_engine(
                settings.DATABASE_URL,
                echo=settings.DEBUG,
                poolclass=NullPool,  # SQLite doesn't support connection pooling well
            )
        else:
            engine = create_async_engine(
                settings.DATABASE_URL,
                echo=settings.DEBUG,
                pool_size=settings.DATABASE_POOL_SIZE,
                max_overflow=settings.DATABASE_MAX_OVERFLOW,
                pool_pre_ping=True,  # Verify connections before using
            )

        self.engine = engine
        self.session_maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        return engine

    async def init_db(self) -> None:
        """Initialize database and create tables"""
        if self.engine is None:
            self.init_engine()

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        self._initialized = True

    async def close(self) -> None:
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()
            self._initialized = False

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session"""
        if self.session_maker is None:
            self.init_engine()

        async with self.session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens"""
        from .models import OAuthToken

        async with self.session_maker() as session:
            return await OAuthToken.cleanup_expired_tokens(session)


# Global instance
db_manager = DatabaseManager()


# Dependency for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database sessions

    Usage:
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(BitcoinCashUser))
            return result.scalars().all()
    """
    async for session in db_manager.get_session():
        yield session
