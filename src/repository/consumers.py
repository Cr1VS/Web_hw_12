from typing import Optional
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from sqlalchemy.ext.asyncio import AsyncSession
from libgravatar import Gravatar
from sqlalchemy import select
from fastapi import Depends


from customs.custom_logger import logger
from schemas.consumer import UserSchema
from entity.models import Consumer
from database.db import get_db


async def get_user_by_email(
    email: str, db: AsyncSession = Depends(get_db)
) -> Optional[Consumer]:
    """
    Retrieves a user by email from the database.

    Args:
        email (str): The email address of the user.
        db (AsyncSession, optional): The asynchronous database session.

    Returns:
        Optional[Consumer]: The user retrieved from the database, or None if not found.
    """
    async with db as session:
        stmt = select(Consumer).filter_by(email=email)
        user = await session.execute(stmt)
        return user.scalar_one_or_none()


async def create_user(body: UserSchema, db: AsyncSession = Depends(get_db)) -> Consumer:
    """
    Creates a new user in the database.

    Args:
        body (UserSchema): The data of the user to be created.
        db (AsyncSession, optional): The asynchronous database session.

    Returns:
        Consumer: The user that was created in the database.
    """
    avatar = None
    try:
        g = Gravatar(body.email)
        avatar = g.get_image()
    except Exception as e:
        logger.log(f"Error fetching avatar for user {body.email}: {e}")

    new_user = Consumer(**body.model_dump(), avatar=avatar)
    async with db as session:
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
    return new_user


async def update_token(user: Consumer, token: Optional[str], db: AsyncSession) -> None:
    """
    Updates the refresh token for a user in the database.

    Args:
        user (Consumer): The user whose token is to be updated.
        token (str, optional): The new refresh token value.
        db (AsyncSession): The asynchronous database session.
    """
    user.refresh_token = token
    async with db as session:
        await session.commit()
