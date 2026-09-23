from fastapi import APIRouter, Depends, HTTPException, UploadFile, File

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.imagecheck import analyze_image


router = APIRouter(
    prefix="/imagecheck",
    tags=["Image Check"]
)


@router.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    data = await file.read()

    if len(data) == 0:
        raise HTTPException(status_code=400, detail="الملف فارغ")

    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="الملف كبير جداً (الحد 20MB)")

    return analyze_image(file.filename or "unknown", data)