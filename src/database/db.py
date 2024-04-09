from typing import AsyncGenerator, Optional
import contextlib
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine, AsyncSession


from customs.custom_logger import logger
from config.conf import config


class DatabaseSessionManager:
    """
    Manages database sessions asynchronously.

    Args:
        url (str): The URL of the database.

    Attributes:
        _engine (AsyncEngine): The asynchronous database engine.
        _session_maker (async_sessionmaker): The asynchronous session maker.
    """

    def __init__(self, url: str):
        self._engine: Optional[AsyncEngine] = create_async_engine(url)
        self._session_maker: async_sessionmaker = async_sessionmaker(
            autoflush=False, autocommit=False, bind=self._engine
        )

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Asynchronously creates and yields a database session.

        Yields:
            AsyncSession: The database session.

        Raises:
            Exception: If the session is not initialized.
        """
        if self._session_maker is None:
            raise Exception("Session is not initialized")
        session = self._session_maker()
        try:
            yield session
        except Exception as err:
            logger.log(err, level=40)
            await session.rollback()
        finally:
            await session.close()

sessionmanager = DatabaseSessionManager(config.DB_URL)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Asynchronously yields a database session.

    Yields:
        AsyncSession: The database session.
    """
    async with sessionmanager.session() as session:
        yield session
    


    