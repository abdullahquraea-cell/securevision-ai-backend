from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.filediscovery import discover_files
from app.scanner.guard import validate_target


router = APIRouter(
    prefix="/filediscovery",
    tags=["FileDiscovery"]
)


class FileDiscoveryRequest(BaseModel):
    url: str
    consent: bool = False


@router.post("/scan")
def scan(
    data: FileDiscoveryRequest,
    current_user: User = Depends(get_current_user),
):
    if not data.url.strip():
        raise HTTPException(status_code=400, detail="أدخل رابط الموقع")

    try:
        validate_target(data.url, consent=data.consent)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return discover_files(data.url)