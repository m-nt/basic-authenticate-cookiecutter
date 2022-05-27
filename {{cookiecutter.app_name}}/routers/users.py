from fastapi import APIRouter
from models.base_models import User, UpdateUser, ReturnUser

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)


@router.get("/login",response_description="Login to the app", response_model=ReturnUser)
async def login():
    pass
