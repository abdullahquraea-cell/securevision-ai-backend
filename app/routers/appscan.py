"""
راوتر فحص التطبيقات — يدعم:
- رفع ملفّ (APK/IPA/EXE/ELF/DMG/MSI/DEB)
- رابط Play Store / App Store / رابط مباشر
"""
import os
import tempfile

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.routers.auth import get_current_user
from ..scanner import appscan as scanner

router = APIRouter(prefix="/appscan", tags=["appscan"])

# 200 MB حدّ أعلى لرفع تطبيق (يمكن تعديله لاحقاً حسب الخطّة)
MAX_UPLOAD_BYTES = 200 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".apk", ".aab", ".xapk",              # Android
    ".ipa",                                # iOS
    ".exe", ".dll", ".msi",                # Windows
    ".elf", ".deb", ".rpm", ".appimage",   # Linux
    ".dmg", ".pkg", ".app",                # macOS
    ".jar",                                # Java
}


@router.post("/upload")
async def upload_and_analyze(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """يستقبل ملفّ تطبيق، يكشف نوعه، ويُرجع تحليلاً أوّليّاً."""
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"نوع الملفّ غير مدعوم ({ext or 'بدون امتداد'}). "
                   f"المدعوم: APK/IPA/EXE/DLL/MSI/ELF/DEB/DMG/PKG/APP/JAR",
        )

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    total = 0
    try:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"الملفّ أكبر من الحدّ المسموح (200 MB).",
                )
            tmp.write(chunk)
        tmp.close()

        result = scanner.analyze_file(tmp.name, original_name=filename)
        return result
    finally:
        try:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
        except Exception:
            pass


class UrlScanRequest(BaseModel):
    url: str


@router.post("/analyze-url")
async def analyze_url(
    body: UrlScanRequest,
    current_user=Depends(get_current_user),
):
    """يفحص تطبيقاً عبر رابط: Play Store / App Store / رابط مباشر."""
    from ..scanner import url_scanner
    return url_scanner.scan_url(body.url)