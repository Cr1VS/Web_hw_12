import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from fastapi.security import (
    OAuth2PasswordRequestForm,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession


from schemas.consumer import UserSchema, TokenSchema, UserResponse
from repository import consumers as repository_consumer
from services.auth import auth_service
from database.db import get_db
from sqlalchemy.exc import SQLAlchemyError

router = APIRouter(prefix="/auth", tags=["auth"])
get_refresh_token = HTTPBearer()


@router.post(
    "/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def signup(body: UserSchema, db: AsyncSession = Depends(get_db)) -> UserResponse:
    """
    Creates a new user account.

    Args:
        body (UserSchema): The data of the user to be created.
        db (AsyncSession, optional): The asynchronous database session.

    Returns:
        UserResponse: The user account that was created.
    """
    try:
        exist_user = await repository_consumer.get_user_by_email(body.email, db)
        if exist_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Account already exists"
            )
        
        body.password = auth_service.get_password_hash(body.password)
        new_user = await repository_consumer.create_user(body, db)
        return new_user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error"
        )
    
    
@router.post("/login", response_model=TokenSchema)
async def login(
    body: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
) -> TokenSchema:
    """
    Logs in a user and returns access and refresh tokens.

    Args:
        body (OAuth2PasswordRequestForm): The login form data.
        db (AsyncSession, optional): The asynchronous database session.

    Returns:
        TokenSchema: The access and refresh tokens.
    """
    user = await repository_consumer.get_user_by_email(body.username, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email"
        )
    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    access_token = await auth_service.create_access_token(
        data={"sub": user.email, "test": "Сергій Багмет"}
    )
    refresh_token = await auth_service.create_refresh_token(data={"sub": user.email})
    await repository_consumer.update_token(user, refresh_token, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get("/refresh_token", response_model=TokenSchema)
async def refresh_token(
    credentials: HTTPAuthorizationCredentials = Depends(get_refresh_token),
    db: AsyncSession = Depends(get_db),
) -> TokenSchema:
    """
    Refreshes an access token using a refresh token.

    Args:
        credentials (HTTPAuthorizationCredentials): The HTTP authorization credentials containing the refresh token.
        db (AsyncSession, optional): The asynchronous database session.

    Returns:
        TokenSchema: The new access and refresh tokens.
    """
    token = credentials.credentials
    email = await auth_service.decode_refresh_token(token)
    user = await repository_consumer.get_user_by_email(email, db)
    if user.refresh_token != token:
        await repository_consumer.update_token(user, None, db)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    access_token = await auth_service.create_access_token(data={"sub": email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": email})
    await repository_consumer.update_token(user, refresh_token, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

