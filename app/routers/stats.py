from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding

from app.routers.auth import get_current_user


router = APIRouter(prefix="/stats", tags=["Stats"])


def _engine_of(title: str) -> str:
    t = title or ""
    if t.startswith("[Nmap]"):
        return "Nmap"
    if t.startswith("[Nuclei]"):
        return "Nuclei"
    if t.startswith("[SQLMap]"):
        return "SQLMap"
    return "SecureVision"


@router.get("/overview")
def overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    is_admin = current_user.role == "admin"

    projects_q = db.query(Project)
    scans_q = db.query(Scan)
    findings_q = db.query(Finding)

    if not is_admin:
        owned_ids = [
            p.id for p in db.query(Project).filter(
                Project.owner_id == current_user.id
            ).all()
        ]
        projects_q = projects_q.filter(Project.owner_id == current_user.id)
        scans_q = scans_q.filter(Scan.owner_id == current_user.id)
        findings_q = findings_q.filter(Finding.project_id.in_(owned_ids or [0]))

    total_projects = projects_q.count()
    total_scans = scans_q.count()

    all_findings = findings_q.all()
    all_scans = scans_q.all()
    total_findings = len(all_findings)

    # توزيع الخطورة + الأدوات
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    engines = {"Nmap": 0, "Nuclei": 0, "SQLMap": 0, "SecureVision": 0}
    for f in all_findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
        engines[_engine_of(f.title)] += 1

    # حالة الفحوصات
    scan_status = {"completed": 0, "running": 0, "failed": 0}
    for s in all_scans:
        if s.status in scan_status:
            scan_status[s.status] += 1

    # درجة الأمان
    penalty = (
        severity_counts["critical"] * 15 +
        severity_counts["high"] * 8 +
        severity_counts["medium"] * 3 +
        severity_counts["low"] * 1
    )
    security_score = max(0, 100 - penalty)

    # اتجاه آخر 7 أيام
    today = datetime.now().date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    f_by_day = {d: 0 for d in days}
    s_by_day = {d: 0 for d in days}
    for f in all_findings:
        try:
            d = f.created_at.date()
            if d in f_by_day:
                f_by_day[d] += 1
        except Exception:
            pass
    for s in all_scans:
        try:
            d = s.created_at.date()
            if d in s_by_day:
                s_by_day[d] += 1
        except Exception:
            pass
    trend = [
        {"day": d.strftime("%m-%d"), "findings": f_by_day[d], "scans": s_by_day[d]}
        for d in days
    ]

    # آخر الفحوصات
    recent_scans = []
    for s in scans_q.order_by(Scan.id.desc()).limit(5).all():
        project = db.query(Project).filter(Project.id == s.project_id).first()
        recent_scans.append({
            "id": s.id,
            "project_name": project.name if project else "—",
            "scan_type": s.scan_type,
            "status": s.status,
            "findings_count": s.findings_count,
        })

    # آخر الثغرات
    recent_findings = []
    for f in findings_q.order_by(Finding.id.desc()).limit(6).all():
        recent_findings.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "engine": _engine_of(f.title),
        })

    return {
        "is_admin": is_admin,
        "total_projects": total_projects,
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical_count": severity_counts["critical"],
        "security_score": security_score,
        "severity": severity_counts,
        "engines": engines,
        "scan_status": scan_status,
        "trend": trend,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
    }