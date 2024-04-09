from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text


from src.customs.custom_logger import logger
from src.routes import users, auth
from src.database.db import get_db


app = FastAPI()


app.include_router(users.router, prefix="/api")
app.include_router(auth.router, prefix="/api")


@app.get("/")
def index() -> dict:
    """
    Main endpoint returning a message indicating the Todo Application.
    """
    return {"message": "Todo Application"}


@app.get("/api/healthchecker")
async def healthchecker(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Endpoint for checking the health of the application and database connection.

    Args:
        db (AsyncSession): An asynchronous database session.

    Returns:
        dict: A message indicating the status of the application and database connection.
    """
    try:
        result = await db.execute(text("SELECT 1"))
        result = result.fetchone()
        if result is None:
            raise HTTPException(status_code=500, detail="Database is not configured correctly")
        return {"message": "Welcome to FastAPI!"}
    except Exception as e:
        logger.log(e, level=40)
        raise HTTPException(status_code=500, detail="Error connecting to the database")
