from datetime import datetime, timedelta
from typing import Union
from fastapi import Depends, FastAPI, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from models.base_models import User, ReturnUser, RegisterUser, LoginUser
from tools.useful import valitdatePassword, validateUsername, create_user
import motor.motor_asyncio
import os
import dotenv

dotenv.load_dotenv()
client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv("MONGODB_URL"))
db_name = "{{cookiecutter.app_name}}"
db = client[db_name]

app = FastAPI()


@app.post("/register", response_model=ReturnUser)
async def register(user: RegisterUser = Body()):
    valitdatePassword(user.password)
    validateUsername(user.username)
    user_instant = await db["users"].find_one({"Username": user.username})
    if user_instant:
        raise HTTPException(400, "this user is already taken!")
    return create_user(db, user)


@app.post("/login", response_model=User)
async def login(user: LoginUser = Body()):
    pass
