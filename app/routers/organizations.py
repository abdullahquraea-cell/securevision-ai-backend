from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.routers.auth import get_current_user
from app.security.password import hash_password


router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"]
)

ORG_ROLES = ["owner", "admin", "member"]


# ==========================
# Schemas
# ==========================

class OrgRename(BaseModel):
    name: str


class InviteMember(BaseModel):
    username: str
    email: str
    password: str
    org_role: str = "member"


class ChangeRole(BaseModel):
    org_role: str


def _require_org_manager(user: User):
    """يجب أن يكون owner أو admin لإدارة المؤسسة."""
    if getattr(user, "org_role", "member") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="ليست لديك صلاحية إدارة المؤسسة")


# ==========================
# معلومات مؤسستي + الأعضاء
# ==========================

@router.get("/me")
def my_organization(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if not org:
        raise HTTPException(status_code=404, detail="لا توجد مؤسسة مرتبطة بحسابك")

    members = db.query(User).filter(
        User.organization_id == org.id
    ).all()

    return {
        "id": org.id,
        "name": org.name,
        "plan": org.plan,
        "owner_id": org.owner_id,
        "my_role": current_user.org_role,
        "members_count": len(members),
        "members": [
            {
                "id": m.id,
                "username": m.username,
                "email": m.email,
                "org_role": m.org_role,
                "is_verified": getattr(m, "is_verified", True),
                "is_owner": m.id == org.owner_id,
            }
            for m in members
        ],
    }


# ==========================
# إعادة تسمية المؤسسة
# ==========================

@router.put("/rename")
def rename_organization(
    payload: OrgRename,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_org_manager(current_user)

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if not org:
        raise HTTPException(status_code=404, detail="المؤسسة غير موجودة")

    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="الاسم مطلوب")

    org.name = name
    db.commit()
    return {"message": "تم تحديث اسم المؤسسة ✅", "name": org.name}


# ==========================
# دعوة / إضافة عضو
# ==========================

@router.post("/invite")
def invite_member(
    payload: InviteMember,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_org_manager(current_user)

    if payload.org_role not in ORG_ROLES or payload.org_role == "owner":
        raise HTTPException(status_code=400, detail="دور غير صالح")

    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="كلمة المرور 6 أحرف على الأقل")

    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="البريد مستخدم مسبقاً")

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="اسم المستخدم مستخدم مسبقاً")

    new_member = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="analyst",
        organization_id=current_user.organization_id,
        org_role=payload.org_role,
        is_verified=True,   # يُضاف مباشرة من قبل المدير
    )
    db.add(new_member)
    db.commit()
    db.refresh(new_member)

    return {
        "message": "تمت إضافة العضو للمؤسسة ✅",
        "member": {
            "id": new_member.id,
            "username": new_member.username,
            "email": new_member.email,
            "org_role": new_member.org_role,
        },
    }


# ==========================
# تغيير دور عضو
# ==========================

@router.put("/members/{member_id}/role")
def change_member_role(
    member_id: int,
    payload: ChangeRole,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_org_manager(current_user)

    if payload.org_role not in ("admin", "member"):
        raise HTTPException(status_code=400, detail="دور غير صالح")

    member = db.query(User).filter(
        User.id == member_id,
        User.organization_id == current_user.organization_id,
    ).first()

    if not member:
        raise HTTPException(status_code=404, detail="العضو غير موجود في مؤسستك")

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()
    if org and member.id == org.owner_id:
        raise HTTPException(status_code=400, detail="لا يمكن تغيير دور مالك المؤسسة")

    member.org_role = payload.org_role
    db.commit()
    return {"message": "تم تحديث الدور ✅"}


# ==========================
# إزالة عضو
# ==========================

@router.delete("/members/{member_id}")
def remove_member(
    member_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_org_manager(current_user)

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if org and member_id == org.owner_id:
        raise HTTPException(status_code=400, detail="لا يمكن إزالة مالك المؤسسة")

    if member_id == current_user.id:
        raise HTTPException(status_code=400, detail="لا يمكنك إزالة نفسك")

    member = db.query(User).filter(
        User.id == member_id,
        User.organization_id == current_user.organization_id,
    ).first()

    if not member:
        raise HTTPException(status_code=404, detail="العضو غير موجود في مؤسستك")

    db.delete(member)
    db.commit()
    return {"message": "تمت إزالة العضو ✅"}