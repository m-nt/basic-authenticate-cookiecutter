from datetime import datetime, timedelta
from typing import Union
from fastapi import Depends, FastAPI, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from models.base_models import UpdateUser, User, ReturnUser, RegisterUser, LoginUser
from tools.useful import (
    valitdatePassword,
    validateUsername,
    create_user,
    verify_password,
)
import motor.motor_asyncio
import os
import dotenv
from fastapi.encoders import jsonable_encoder
import time

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "{{cookiecutter.secret_key}}"
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


async def loggin(pwd_context: CryptContext, user: LoginUser, type: str):
    if type == "username":
        user_instant = await db["users"].find_one({type: user.username})
    else:
        user_instant = await db["users"].find_one({type: user.email})
    if user_instant is None:
        raise HTTPException(400, "User not found!")
    user_instant = User.parse_obj(user_instant)
    verify_password(pwd_context, user.password, user_instant.password)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_instant.username}, expires_delta=access_token_expires
    )
    user_instant.token = access_token
    update_user = jsonable_encoder(user_instant)
    result = await db["users"].update_one(
        {"username": user_instant.username}, {"$set": update_user}
    )
    if result is None:
        raise HTTPException(500, "some thing happend!")
    print(result)
    return ReturnUser.parse_obj(user_instant)


dotenv.load_dotenv()
client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv("MONGODB_URL"))
db = client["twatter"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()


@app.post("/register", response_model=ReturnUser)
async def register(user: RegisterUser = Body()):
    if user.username is None and user.email is None:
        raise HTTPException(400, "username or email must be included!")
    valitdatePassword(user.password)
    user_instant_username = None
    user_instant_email = None
    if user.username is not None:
        validateUsername(user.username)
        user_instant_username = await db["users"].find_one({"username": user.username})
    if user.email is not None:
        user_instant_email = await db["users"].find_one({"email": user.email})
    if user_instant_username or user_instant_email:
        raise HTTPException(400, "This user is already taken!")
    return await create_user(client, RegisterUser.parse_obj(user), pwd_context)


class Token(BaseModel):
    token: str


@app.post("/token/login", response_model=ReturnUser)
async def token_login(token: Token = Body()):
    if token.token is None:
        raise HTTPException(400, "token should be specified!")
    try:
        payload = jwt.decode(token.token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        expire: int = payload.get("exp")
        if username is None or expire is None:
            raise HTTPException(401, "Could not validate credentials")
    except JWTError:
        raise HTTPException(401, "Could not validate credentials")
    if expire - time.time() <= 0:
        raise HTTPException(401, "Could not validate credentials")
    user_instant = await db["users"].find_one({"username": username})
    if user_instant is None:
        raise HTTPException(400, "User not found!")
    user_instant = User.parse_obj(user_instant)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_instant.username}, expires_delta=access_token_expires
    )
    user_instant.token = access_token
    update_user = jsonable_encoder(user_instant)
    await db["users"].update_one(
        {"username": user_instant.username}, {"$set": update_user}
    )
    return ReturnUser.parse_obj(user_instant)


@app.post("/login", response_model=ReturnUser)
async def login(user: LoginUser = Body()):
    if user.username is None and user.email is None:
        raise HTTPException(400, "username or email must be included!")
    if user.username:
        validateUsername(user.username)
        return await loggin(pwd_context, user, "username")
    if user.email:
        return await loggin(pwd_context, user, "email")
