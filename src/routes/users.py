from typing import List, Optional
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from fastapi import APIRouter, HTTPException, Depends, status, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession


from schemas.user import UserSchema, UserResponse
from repository import users as repository_users
from entity.models import Consumer, Role
from services.auth import auth_service
from services.roles import RoleAccess
from database.db import get_db


router = APIRouter(prefix="/users", tags=["users"])


access_to_route_all = RoleAccess([Role.ADMIN, Role.MODERATOR])


@router.get("/", response_model=List[UserResponse])
async def get_users(
    limit: int = Query(10, ge=10, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> List[UserResponse]:
    """
    Retrieves a list of users from the database.

    Args:
        limit (int): The maximum number of users to retrieve.
        offset (int): The offset for pagination.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        List[UserResponse]: A list of users retrieved from the database.
    """
    users = await repository_users.get_users(limit, offset, db, c_user)
    return users


@router.get(
    "/all",
    response_model=List[UserResponse],
    dependencies=[Depends(access_to_route_all)],
)
async def get_all_users(
    limit: int = Query(10, ge=10, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> List[UserResponse]:
    """
    Retrieves a list of all users from the database.

    Args:
        limit (int): The maximum number of users to retrieve.
        offset (int): The offset for pagination.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        List[UserResponse]: A list of users retrieved from the database.
    """
    users = await repository_users.get_all_users(limit, offset, db)
    return users


@router.get("/birth_date", response_model=List[UserResponse])
async def get_users_birth(
    limit: int = Query(7, ge=7, le=100),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> List[UserResponse]:
    """
    Retrieves users from the database whose birthdays fall within a specified limit.

    Args:
        limit (int): The limit for the range of birthdays.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        List[UserResponse]: A list of users retrieved from the database.
    """
    users = await repository_users.get_users_birth(limit, db, c_user)
    return users


@router.get("/search_by", response_model=List[UserResponse])
async def get_users_by(
    first_name: Optional[str] = Query(
        None, min_length=3, description="Frist name search query"
    ),
    second_name: Optional[str] = Query(
        None, min_length=3, description="Second name search query"
    ),
    email_add: Optional[str] = Query(
        None, min_length=3, description="Email search query"
    ),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> List[UserResponse]:
    """
    Retrieves users from the database based on specified criteria.

    Args:
        first_name (str, optional): The first name of the user.
        second_name (str, optional): The second name of the user.
        email_add (str, optional): The email address of the user.
        db (AsyncSession, optional): The asynchronous database session.
        c_user (Consumer, optional): The current authenticated user.

    Returns:
        List[UserResponse]: A list of users retrieved from the database.
    """
    users = await repository_users.get_users_by(
        first_name, second_name, email_add, db, c_user
    )
    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> UserResponse:
    """
    Retrieves a user from the database by ID.

    Args:
        user_id (int): The ID of the user to retrieve.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        UserResponse: The user retrieved from the database.
    """
    user = await repository_users.get_user(user_id, db, c_user)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT FOUND")
    return user


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserSchema,
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> UserResponse:
    """
    Creates a new user in the database.

    Args:
        body (UserSchema): The data of the user to be created.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        UserResponse: The user that was created in the database.
    """
    user = await repository_users.create_user(body, db, c_user)
    return user


@router.put("/{user_id}")
async def update_user(
    body: UserSchema,
    user_id: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> UserResponse:
    """
    Updates an existing user in the database.

    Args:
        body (UserSchema): The updated data for the user.
        user_id (int): The ID of the user to be updated.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        UserResponse: The user that was updated in the database.
    """
    user = await repository_users.update_user(user_id, body, db, c_user)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT FOUND")
    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    c_user: Consumer = Depends(auth_service.get_current_user),
) -> UserResponse:
    """
    Deletes a user from the database.

    Args:
        user_id (int): The ID of the user to be deleted.
        db (AsyncSession): The asynchronous database session.
        c_user (Consumer): The current authenticated user.

    Returns:
        UserResponse: The user that was deleted from the database.
    """
    user = await repository_users.delete_user(user_id, db, c_user)
    return user
