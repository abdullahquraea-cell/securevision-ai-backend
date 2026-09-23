from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.codescan import scan_code


router = APIRouter(prefix="/codescan", tags=["CodeScan"])


class CodeRequest(BaseModel):
    code: str
    filename: str = ""


@router.post("/scan")
def scan(
    data: CodeRequest,
    current_user: User = Depends(get_current_user),
):
    if not data.code.strip():
        raise HTTPException(status_code=400, detail="ألصق كوداً للفحص")
    return scan_code(data.code, data.filename)