from datetime import datetime, timedelta
from typing import Union
from fastapi import Depends, FastAPI, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from models.base_models import User, ReturnUser, RegisterUser, LoginUser
from tools.useful import (
    valitdatePassword,
    validateUsername,
    create_user,
    verify_password,
    credentials_exception,
)
import motor.motor_asyncio
import os
import dotenv

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "ddaeb443ef33f62a0a8c732eb1ba822f4390e3aafd590e2d08144fc19e19e438"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


dotenv.load_dotenv()
client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv("MONGODB_URL"))
db_name = "{{cookiecutter.app_name}}"
db = client[db_name]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


@app.post("/register", response_model=ReturnUser)
async def register(user: RegisterUser = Body()):
    if user.username is None and user.email is None:
        raise HTTPException(400, "username or email must be included!")
    valitdatePassword(user.password)
    user_instant = None
    if user.username:
        validateUsername(user.username)
        user_instant = await db["users"].find_one({"username": user.username})
    else:
        user_instant = await db["users"].find_one({"email": user.email})
    if user_instant:
        raise HTTPException(400, "this user is already taken!")
    return create_user(db, user)


@app.post("/login", response_model=User)
async def login(user: LoginUser = Body()):
    if user.username is None and user.email is None:
        raise HTTPException(400, "username or email must be included!")
    user_instant = None
    if user.token:
        payload = jwt.decode(user.token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user_instant = await db["users"].find_one({"username": user.username})
        user_instant = User.parse_obj(user_instant)
        verify_password(user.password, user_instant.password)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_instant.username}, expires_delta=access_token_expires
        )
        user_instant.token = access_token
        await db["users"].update_one(
            {"username": user_instant.username}, {"token": user_instant.token}
        )
        return user_instant
    if user.username:
        validateUsername(user.username)
        user_instant = await db["users"].find_one({"username": user.username})
        user_instant = User.parse_obj(user_instant)
        verify_password(user.password, user_instant.password)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_instant.username}, expires_delta=access_token_expires
        )
        user_instant.token = access_token
        await db["users"].update_one(
            {"username": user_instant.username}, {"token": user_instant.token}
        )
        return user_instant
    if user.email:
        user_instant = await db["users"].find_one({"email": user.email})
        user_instant = User.parse_obj(user_instant)
        verify_password(user.password, user_instant.password)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_instant.username}, expires_delta=access_token_expires
        )
        user_instant.token = access_token
        await db["users"].update_one(
            {"username": user_instant.username}, {"token": user_instant.token}
        )
        return user_instant
