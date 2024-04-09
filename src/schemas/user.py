from datetime import date, datetime
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from pydantic import BaseModel, EmailStr, Field


from schemas.consumer import UserResponse


class UserSchema(BaseModel):
    """
    Schema representing user data for input validation.
    """

    first_name: str = Field(
        ..., description="First name of the user", min_length=3, max_length=50
    )
    second_name: str = Field(
        ..., description="Second name of the user", min_length=3, max_length=50
    )
    email_add: EmailStr = Field(..., description="Email address of the user")
    phone_num: str = Field(..., description="Phone number of the user")
    birth_date: date = Field(..., description="Birth date of the user")


class UserResponse(BaseModel):
    """
    Schema representing user data for response.
    """

    id: int = Field(description="Identifier of the user")
    first_name: str = Field(description="First name of the user")
    second_name: str = Field(description="Second name of the user")
    email_add: EmailStr = Field(description="Email address of the user")
    phone_num: str = Field(description="Phone number of the user")
    birth_date: date = Field(description="Birth date of the user")
    consumer: UserResponse | None = Field(description="Related consumer data")
    created_at: datetime = Field(description="Creation timestamp of the user")
    updated_at: datetime = Field(description="Update timestamp of the user")

    class Config:
        """
        Configuration class for UserResponse.
        """

        from_attributes = True
