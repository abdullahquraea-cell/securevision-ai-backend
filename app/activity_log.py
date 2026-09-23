from sqlalchemy.orm import Session

from app.models.activity import Activity


def log_activity(
    db: Session,
    user_id: int,
    username: str,
    action: str,
    details: str = "",
) -> None:
    """تسجيل حدث في سجل النشاط."""
    entry = Activity(
        user_id=user_id,
        username=username,
        action=action,
        details=details,
    )
    db.add(entry)
    db.commit()