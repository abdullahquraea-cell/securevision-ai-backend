from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.urlcheck import analyze_url


router = APIRouter(
    prefix="/urlcheck",
    tags=["URL Check"]
)


class UrlIn(BaseModel):
    url: str


@router.post("/analyze")
def analyze(
    data: UrlIn,
    current_user: User = Depends(get_current_user)
):
    if not data.url.strip():
        raise HTTPException(status_code=400, detail="الرابط فارغ")

    return analyze_url(data.url)