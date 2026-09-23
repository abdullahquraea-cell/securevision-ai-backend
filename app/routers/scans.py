from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan

from app.routers.auth import get_current_user

from app.scanner.engine import run_scan
from app.scanner.live import run_live_scan, SCANS
from app.scanner.guard import validate_target
from app.routers.subscription import PLANS
from datetime import datetime

from app.activity_log import log_activity


router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


class ScanCreate(BaseModel):
    project_id: int
    scan_type: str = "full"
    consent: bool = False   # تأكيد ملكية الهدف (للأهداف الخارجية)


# ==========================
# List Scans
# ==========================

@router.get("")
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Scan)

    # مدير المنصّة يرى الكل، وبقية المستخدمين يرون فحوصات مؤسستهم
    if current_user.role != "admin":
        org_project_ids = [
            p.id for p in db.query(Project).filter(
                Project.organization_id == current_user.organization_id
            ).all()
        ]
        query = query.filter(Scan.project_id.in_(org_project_ids))

    scans = query.order_by(Scan.id.desc()).all()

    result = []
    for s in scans:
        project = db.query(Project).filter(
            Project.id == s.project_id
        ).first()
        result.append({
            "id": s.id,
            "project_id": s.project_id,
            "project_name": project.name if project else "—",
            "scan_type": s.scan_type,
            "status": s.status,
            "findings_count": s.findings_count,
            "created_at": s.created_at,
        })
    return result


# ==========================
# Start Live Scan (background)
# ==========================

@router.post("/start")
def start_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    project = db.query(Project).filter(
        Project.id == data.project_id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # السماح بالفحص لأعضاء نفس المؤسسة (أو مدير المنصّة)
    if (
        current_user.role != "admin"
        and project.organization_id != current_user.organization_id
    ):
        raise HTTPException(status_code=403, detail="Not allowed to scan this project")

    if not project.target.strip():
        raise HTTPException(
            status_code=400,
            detail="هذا المشروع لا يحتوي على هدف (target) للفحص"
        )

    # ===== الحارس القانوني: منع فحص ما لا تملكه =====
    try:
        validate_target(project.target, consent=data.consent)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # ===== فرض حد الباقة على الفحوصات الشهرية =====
    plan = getattr(current_user, "plan", "free") or "free"
    monthly_limit = PLANS.get(plan, PLANS["free"]).get("scans_per_month", -1)
    if monthly_limit != -1:
        now = datetime.now()
        used = 0
        for s in db.query(Scan).filter(Scan.owner_id == current_user.id).all():
            try:
                if s.created_at.year == now.year and s.created_at.month == now.month:
                    used += 1
            except Exception:
                pass
        if used >= monthly_limit:
            raise HTTPException(
                status_code=403,
                detail=f"بلغت حد باقتك ({monthly_limit} فحوصات هذا الشهر). رقِّ باقتك من صفحة الاشتراك للمزيد.",
            )

    # إنشاء سجل الفحص بحالة running
    scan = Scan(
        project_id=project.id,
        scan_type=data.scan_type,
        status="running",
        owner_id=current_user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_activity(
        db, current_user.id, current_user.username,
        "run_scan", f"بدء فحص مشروع {project.name}"
    )

    # تشغيل الفحص في الخلفية
    background_tasks.add_task(
        run_live_scan,
        scan.id,
        project.id,
        project.target,
        data.scan_type,
        current_user.id,
    )

    return {"scan_id": scan.id, "status": "running"}


# ==========================
# Scan Status (polling)
# ==========================

@router.get("/{scan_id}/status")
def scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    data = SCANS.get(scan_id)
    if data:
        return data

    # غير موجود في الذاكرة — نقرأ الحالة الحقيقية من قاعدة البيانات
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        finished = scan.status in ("completed", "failed")
        return {
            "status": scan.status,
            "progress": 100 if finished else 0,
            "logs": [],
            "findings_count": scan.findings_count,
        }

    return {
        "status": "unknown",
        "progress": 0,
        "logs": [],
        "findings_count": 0,
    }