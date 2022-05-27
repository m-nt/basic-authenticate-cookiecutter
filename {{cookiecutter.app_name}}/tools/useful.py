import motor.motor_asyncio
from models.base_models import User, ReturnUser, RegisterUser
from passlib.context import CryptContext
from fastapi import HTTPException
import re


def get_user(client: motor.motor_asyncio.AsyncIOMotorClient) -> User:
    pass


async def create_user(
    db: motor.motor_asyncio.AsyncIOMotorClient, user: RegisterUser
) -> ReturnUser:
    created_user = User.parse_obj(user)
    res = await db["users"].insert_one(created_user)
    new_user = await db["users"].find_one({"_id": res._id})


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
    if len(res) <= 0:
        raise HTTPException(
            400, "Username most not include (&=_'-+,<>) and or more than one '.'!"
        )


