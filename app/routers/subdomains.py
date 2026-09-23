from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.subdomains import enum_subdomains


router = APIRouter(
    prefix="/subdomains",
    tags=["Subdomains"]
)


class SubRequest(BaseModel):
    domain: str


@router.post("/scan")
def scan(
    data: SubRequest,
    current_user: User = Depends(get_current_user),
):
    if not data.domain.strip():
        raise HTTPException(status_code=400, detail="أدخل نطاقاً")
    return enum_subdomains(data.domain)