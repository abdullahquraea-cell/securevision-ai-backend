from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User

from app.routers.auth import get_current_user
from app.security.password import hash_password


router = APIRouter(prefix="/users", tags=["Users"])


ALLOWED_ROLES = ["admin", "analyst", "viewer"]


def require_admin(current_user: User) -> None:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="هذه الصفحة للمدير فقط")


class RoleUpdate(BaseModel):
    role: str


class UserCreateAdmin(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


# ==========================
# List Users
# ==========================

@router.get("")
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    require_admin(current_user)
    users = db.query(User).order_by(User.id).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role, "is_active": u.is_active}
        for u in users
    ]


# ==========================
# Create User (Admin)
# ==========================

@router.post("")
def create_user(
    data: UserCreateAdmin,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    require_admin(current_user)

    if data.role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"صلاحية غير صحيحة. المسموح: {ALLOWED_ROLES}")

    if not data.username.strip() or not data.email.strip():
        raise HTTPException(status_code=400, detail="اسم المستخدم والبريد مطلوبان")

    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="كلمة المرور يجب ألا تقل عن 6 أحرف")

    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="البريد مستخدم مسبقاً")

    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="اسم المستخدم مستخدم مسبقاً")

    new_user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=data.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role,
    }


# ==========================
# Update User Role
# ==========================

@router.put("/{user_id}/role")
def update_role(
    user_id: int,
    data: RoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    require_admin(current_user)

    if data.role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"صلاحية غير صحيحة. المسموح: {ALLOWED_ROLES}")

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="لا يمكنك تغيير صلاحية حسابك الخاص")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="المستخدم غير موجود")

    user.role = data.role
    db.commit()
    return {"message": "تم تحديث الصلاحية", "role": user.role}


# ==========================
# Delete User
# ==========================

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    require_admin(current_user)

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="لا يمكنك حذف حسابك الخاص")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="المستخدم غير موجود")

    db.delete(user)
    db.commit()
    return {"message": "تم حذف المستخدم"}