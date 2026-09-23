from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.sqlmap_scan import run_sqlmap, is_available
from app.scanner.guard import validate_target


router = APIRouter(
    prefix="/sqlmap",
    tags=["SQLMap"]
)


class SqlmapRequest(BaseModel):
    url: str
    consent: bool = False


@router.post("/test")
def sqlmap_test(
    data: SqlmapRequest,
    current_user: User = Depends(get_current_user),
):
    if not data.url.strip():
        raise HTTPException(status_code=400, detail="أدخل رابطاً يحتوي على معامل (parameter)")

    if not is_available():
        raise HTTPException(
            status_code=500,
            detail="SQLMap غير مثبّت على الخادم"
        )

    # الحارس القانوني — منع فحص ما لا تملكه
    try:
        validate_target(data.url, consent=data.consent)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    result = run_sqlmap(data.url)
    return result