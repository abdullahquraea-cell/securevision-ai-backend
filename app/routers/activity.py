from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.activity import Activity

from app.routers.auth import get_current_user


router = APIRouter(
    prefix="/activity",
    tags=["Activity"]
)


@router.get("")
def list_activity(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # للمدير فقط
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="هذه الصفحة للمدير فقط"
        )

    activities = db.query(Activity).order_by(
        Activity.id.desc()
    ).limit(200).all()

    return [
        {
            "id": a.id,
            "username": a.username,
            "action": a.action,
            "details": a.details,
            "created_at": a.created_at,
        }
        for a in activities
    ]