import asyncio
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from sqlalchemy.ext.asyncio import create_async_engine


from customs.custom_logger import logger
from config.conf import config
from models import Base


engine = create_async_engine(config.DB_URL)


async def create_database_tables() -> None:
    """
    Asynchronously creates database tables based on the models.

    Raises:
        Exception: If an error occurs while creating tables.
    """
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logger.log(f"An error occurred while creating database tables: {e}", level=40)


async def main() -> None:
    """
    Asynchronously runs the main function to create database tables.
    """
    await create_database_tables()


if __name__ == "__main__":
    asyncio.run(main())
