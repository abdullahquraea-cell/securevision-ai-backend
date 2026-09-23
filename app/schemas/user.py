from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):

    username: str

    email: EmailStr

    password: str



class UserResponse(BaseModel):

    id: int

    username: str

    email: str

    role: str

    is_active: bool


    class Config:
        from_attributes = True