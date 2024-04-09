import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from pydantic import BaseModel, EmailStr, Field


from entity.models import Role


class UserSchema(BaseModel):
    """
    Data schema for user input validation.
    """

    username: str = Field(min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(description="Email address")
    password: str = Field(min_length=6, max_length=30, description="Password")


class UserResponse(BaseModel):
    """
    Data schema for user response.
    """

    id: int = Field(description="User identifier")
    username: str = Field(description="Username")
    email: EmailStr = Field(description="Email address")
    avatar: str = Field(default=None, description="URL of user's avatar")
    role: Role = Field(description="User's role")

    class Config:
        """
        Configuration for UserResponse schema.
        """

        from_attributes = True


class TokenSchema(BaseModel):
    """
    Data schema for access token.
    """

    access_token: str = Field(description="Access token")
    refresh_token: str = Field(description="Refresh token")
    token_type: str = Field("bearer", description="Token type")
