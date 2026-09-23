"""
راوتر لوحة تحكّم الأدمن — مقيّد لـ role='admin' فقط.
كلّ الـ endpoints هنا مُحميّة تلقائياً عبر require_admin.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_user

router = APIRouter(prefix="/admin", tags=["Admin"])


def require_admin(user: User = Depends(get_current_user)):
    """يرفض الوصول لأيّ مستخدم ليس role='admin'."""
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="ممنوع — هذا المسار للأدمن فقط"
        )
    return user


def _safe_count(db: Session, sql: str, params: dict = None) -> int:
    """يعدّ الصفوف بأمان — يُرجع 0 إن كان الجدول أو العمود غير موجود."""
    try:
        result = db.execute(text(sql), params or {}).scalar()
        return int(result or 0)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return 0


@router.get("/stats/overview")
def stats_overview(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """يُرجع كلّ إحصائيات المنصّة في طلب واحد."""
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    day_ago = now - timedelta(days=1)

    return {
        "users": {
            "total": _safe_count(db, "SELECT COUNT(*) FROM users"),
            "verified": _safe_count(db, "SELECT COUNT(*) FROM users WHERE is_verified = true"),
            "new_this_week": _safe_count(db, "SELECT COUNT(*) FROM users WHERE created_at >= :d", {"d": week_ago}),
            "new_today": _safe_count(db, "SELECT COUNT(*) FROM users WHERE created_at >= :d", {"d": day_ago}),
        },
        "organizations": {
            "total": _safe_count(db, "SELECT COUNT(*) FROM organizations"),
        },
        "projects": {
            "total": _safe_count(db, "SELECT COUNT(*) FROM projects"),
        },
        "scans": {
            "total": _safe_count(db, "SELECT COUNT(*) FROM scans"),
            "today": _safe_count(db, "SELECT COUNT(*) FROM scans WHERE created_at >= :d", {"d": day_ago}),
            "this_week": _safe_count(db, "SELECT COUNT(*) FROM scans WHERE created_at >= :d", {"d": week_ago}),
            "completed": _safe_count(db, "SELECT COUNT(*) FROM scans WHERE status = 'completed'"),
            "running": _safe_count(db, "SELECT COUNT(*) FROM scans WHERE status = 'running'"),
            "failed": _safe_count(db, "SELECT COUNT(*) FROM scans WHERE status = 'failed'"),
        },
        "findings": {
            "total": _safe_count(db, "SELECT COUNT(*) FROM findings"),
            "critical": _safe_count(db, "SELECT COUNT(*) FROM findings WHERE severity = 'critical'"),
            "high": _safe_count(db, "SELECT COUNT(*) FROM findings WHERE severity = 'high'"),
            "medium": _safe_count(db, "SELECT COUNT(*) FROM findings WHERE severity = 'medium'"),
            "low": _safe_count(db, "SELECT COUNT(*) FROM findings WHERE severity = 'low'"),
            "info": _safe_count(db, "SELECT COUNT(*) FROM findings WHERE severity = 'info'"),
        },
        "subscriptions": {
            "free": _safe_count(db, "SELECT COUNT(*) FROM users WHERE subscription_plan IS NULL OR subscription_plan = 'free'"),
            "pro": _safe_count(db, "SELECT COUNT(*) FROM users WHERE subscription_plan = 'pro'"),
            "enterprise": _safe_count(db, "SELECT COUNT(*) FROM users WHERE subscription_plan = 'enterprise'"),
        },
        "generated_at": now.isoformat(),
    }


@router.get("/stats/user-growth")
def user_growth(
    days: int = 30,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """عدد المستخدمين الجدد يومياً آخر N يوم."""
    try:
        cutoff = datetime.utcnow() - timedelta(days=days)
        rows = db.execute(
            text("""
                SELECT DATE(created_at) AS day, COUNT(*) AS count
                FROM users
                WHERE created_at >= :cutoff
                GROUP BY DATE(created_at)
                ORDER BY day ASC
            """),
            {"cutoff": cutoff},
        ).fetchall()
        return [{"day": str(r[0]), "count": int(r[1])} for r in rows]
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return []