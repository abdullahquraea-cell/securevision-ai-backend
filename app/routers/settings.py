from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User

from app.routers.auth import get_current_user

from app.security.password import hash_password, verify_password


router = APIRouter(
    prefix="/settings",
    tags=["Settings"]
)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


# ==========================
# معلومات الحساب الحالي
# ==========================

@router.get("/me")
def my_settings(
    current_user: User = Depends(get_current_user)
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
    }


# ==========================
# تغيير كلمة المرور
# ==========================

@router.put("/password")
def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # التأكد من كلمة المرور الحالية
    if not verify_password(
        data.current_password,
        current_user.password_hash
    ):
        raise HTTPException(
            status_code=400,
            detail="كلمة المرور الحالية غير صحيحة"
        )

    # التحقق من طول كلمة المرور الجديدة
    if len(data.new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل"
        )

    # حفظ كلمة المرور الجديدة (مشفّرة)
    current_user.password_hash = hash_password(data.new_password)
    db.commit()

    return {"message": "تم تغيير كلمة المرور بنجاح"}