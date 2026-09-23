from fastapi import APIRouter, Depends, HTTPException, UploadFile, File

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.videocheck import analyze_video


router = APIRouter(
    prefix="/videocheck",
    tags=["Video Check"]
)


@router.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    data = await file.read()

    if len(data) == 0:
        raise HTTPException(status_code=400, detail="الملف فارغ")

    if len(data) > 200 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="الملف كبير جداً (الحد 200MB)")

    return analyze_video(file.filename or "unknown", data)