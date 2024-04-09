class Config:
    """
    Class configurations db.
    """

    DB_URL: str = "postgresql+asyncpg://postgres:1234509876@localhost:5432/web_hw_12"


config = Config
