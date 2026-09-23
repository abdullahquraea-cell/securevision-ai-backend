from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.recon import fingerprint
from app.scanner.guard import validate_target


router = APIRouter(
    prefix="/recon",
    tags=["Recon"]
)


class ReconRequest(BaseModel):
    url: str
    consent: bool = False


@router.post("/scan")
def recon_scan(
    data: ReconRequest,
    current_user: User = Depends(get_current_user),
):
    if not data.url.strip():
        raise HTTPException(status_code=400, detail="أدخل رابط الموقع")

    try:
        validate_target(data.url, consent=data.consent)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return fingerprint(data.url)