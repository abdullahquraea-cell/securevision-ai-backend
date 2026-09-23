from datetime import datetime, timedelta, timezone

from jose import jwt

from app.config import settings


# ✅ المفتاح السري يُقرأ الآن من ملف .env (وليس مكتوباً في الكود)
SECRET_KEY = settings.JWT_SECRET_KEY

ALGORITHM = "HS256"

# مدة صلاحية التوكن: 24 ساعة
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24


def create_access_token(data: dict) -> str:

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )