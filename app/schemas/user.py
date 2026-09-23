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

    firebase_uid: str | None = None

    is_verified: bool | None = None

    organization_id: int | None = None

    org_role: str | None = None


    class Config:
        from_attributes = True