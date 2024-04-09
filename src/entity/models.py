from datetime import date
import enum


from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from sqlalchemy import String, Integer, DateTime, ForeignKey, func, Enum


class Base(DeclarativeBase):
    """
    Base class for declarative models.
    """

    pass


class User(Base):
    """
    Model representing users in the database.

    Attributes:
        id (int): The unique identifier of the user.
        first_name (str): The first name of the user.
        second_name (str): The second name of the user.
        phone_num (str): The phone number of the user.
        email_add (str): The email address of the user.
        birth_date (DateTime): The birth date of the user.
        created_at (date): The date and time when the user was created.
        updated_at (date): The date and time when the user was last updated.
        consumer_id (int): The ID of the consumer associated with the user.
        consumer (Consumer): The consumer associated with the user.
    """

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str] = mapped_column(String(50), index=True)
    second_name: Mapped[str] = mapped_column(String(50), index=True)
    phone_num: Mapped[str] = mapped_column(String(25), unique=True, index=True)
    email_add: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    birth_date: Mapped[DateTime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[date] = mapped_column(
        "crated_at", DateTime, default=func.now(), nullable=True
    )
    updated_at: Mapped[date] = mapped_column(
        "updated_at", DateTime, default=func.now(), onupdate=func.now(), nullable=True
    )

    consumer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("consumers.id"), nullable=True
    )
    consumer: Mapped["Consumer"] = relationship(
        "Consumer", backref="users", lazy="joined"
    )


class Role(enum.Enum):
    """
    Enum representing user roles.

    Attributes:
        ADMIN: Administrator role.
        MODERATOR: Moderator role.
        USER: Regular user role.
    """

    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"


class Consumer(Base):
    """
    Model representing consumers in the database.

    Attributes:
        id (int): The unique identifier of the consumer.
        username (str): The username of the consumer.
        email (str): The email address of the consumer.
        password (str): The password of the consumer.
        avatar (str): The avatar URL of the consumer.
        refresh_token (str): The refresh token of the consumer.
        created_at (date): The date and time when the consumer was created.
        updated_at (date): The date and time when the consumer was last updated.
        role (Role): The role of the consumer.
    """

    __tablename__ = "consumers"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50))
    email: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    avatar: Mapped[str] = mapped_column(String(255), nullable=True)
    refresh_token: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[date] = mapped_column("created_at", DateTime, default=func.now())
    updated_at: Mapped[date] = mapped_column(
        "updated_at", DateTime, default=func.now(), onupdate=func.now()
    )
    role: Mapped[Enum[Role]] = mapped_column(
        Enum(Role), default=Role.USER, nullable=False
    )
