import motor.motor_asyncio
from models.base_models import User, ReturnUser, RegisterUser, LoginUser
from passlib.context import CryptContext
from fastapi import HTTPException, status
import re
from datetime import datetime, timedelta
from fastapi.encoders import jsonable_encoder


async def create_user(
    client: motor.motor_asyncio.AsyncIOMotorClient,
    user: RegisterUser,
    pwd_context: CryptContext,
) -> ReturnUser:
    db = client["twatter"]
    created_user = User.parse_obj(user)
    created_user.password = get_password_hash(pwd_context, created_user.password)
    created_user = jsonable_encoder(created_user)
    res = await db["users"].insert_one(created_user)
    new_user = await db["users"].find_one({"_id": res.inserted_id})
    if new_user:
        return ReturnUser.parse_obj(new_user)
    return ReturnUser({})


def verify_password(pwd_context: CryptContext, plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(pwd_context: CryptContext, password):
    return pwd_context.hash(password)


def valitdatePassword(passtext: str):
    if len(passtext) < 6 or len(passtext) > 30:
        raise HTTPException(400, "Password must be between 6 to 30 character!")
    re.findall
    res = re.findall(r"[a-z]+", passtext)
    if len(res) <= 0:
        raise HTTPException(400, "Password must include chars, symbols and numbers")
    res = re.findall(r"[A-Z]+", passtext)
    if len(res) <= 0:
        raise HTTPException(400, "Password must include chars, symbols and numbers")
    res = re.findall(r"[(){}[\]|`¬¦! \"£$%^&*\"<>:;#~_\-+=,@]+", passtext)
    if len(res) <= 0:
        raise HTTPException(400, "Password must include chars, symbols and numbers")
    res = re.findall(r"[0-9]+", passtext)
    if len(res) <= 0:
        raise HTTPException(400, "Password must include chars, symbols and numbers")


def validateUsername(username: str):
    res = re.findall(r"[&=_\'-+,<>]+|\.{2,}", username)
    if len(res) > 0:
        raise HTTPException(
            400, "Username most not include (&=_'-+,<>) and or more than one '.'!"
        )
