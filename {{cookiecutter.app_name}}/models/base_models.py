from pydantic import BaseModel, EmailStr, Field
from typing import Union, Optional
from bson import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


class User(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str
    password: str
    email: Union[EmailStr, None] = None
    full_name: Union[str, None] = None
    token: Union[str, None] = None

    class Config:
        json_encoders = {ObjectId: str}


class RegisterUser(BaseModel):
    username: Union[str, None] = None
    password: str
    email: Union[EmailStr, None] = None
    full_name: Union[str, None] = None


class UpdateUser(BaseModel):
    username: Optional[str]
    password: Optional[str]
    email: Optional[EmailStr]
    full_name: Optional[str]
    token: Optional[str]

    class Config:
        json_encoders = {ObjectId: str}


class LoginUser(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: str

    class Config:
        json_encoders = {ObjectId: str}


class ReturnUser(BaseModel):
    username: str
    email: Union[EmailStr, None] = None
    full_name: Union[str, None] = None
    token: Union[str, None] = None

    class Config:
        json_encoders = {ObjectId: str}
