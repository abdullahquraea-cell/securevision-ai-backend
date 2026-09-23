from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.project import Project
from app.models.finding import Finding

from app.routers.auth import get_current_user


router = APIRouter(
    prefix="/findings",
    tags=["Findings"]
)


def _serialize(f: Finding, project_name: str) -> dict:
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "project_id": f.project_id,
        "project_name": project_name,
        "title": f.title,
        "severity": f.severity,
        "description": f.description,
        "location": f.location,
        "recommendation": f.recommendation,
        "created_at": f.created_at,
    }


# ==========================
# List Findings
# ==========================

@router.get("")
def list_findings(
    severity: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    query = db.query(Finding)

    # المحلل يرى ثغرات مشاريع مؤسسته فقط
    if current_user.role != "admin":
        org_project_ids = [
            p.id for p in db.query(Project).filter(
                Project.organization_id == current_user.organization_id
            ).all()
        ]
        query = query.filter(Finding.project_id.in_(org_project_ids))

    # فلترة حسب الخطورة (اختياري)
    if severity and severity != "all":
        query = query.filter(Finding.severity == severity)

    findings = query.order_by(Finding.id.desc()).all()

    # أسماء المشاريع
    projects = {
        p.id: p.name for p in db.query(Project).all()
    }

    return [
        _serialize(f, projects.get(f.project_id, "—"))
        for f in findings
    ]


# ==========================
# Findings Summary (counts)
# ==========================

@router.get("/summary")
def findings_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    query = db.query(Finding)

    if current_user.role != "admin":
        org_project_ids = [
            p.id for p in db.query(Project).filter(
                Project.organization_id == current_user.organization_id
            ).all()
        ]
        query = query.filter(Finding.project_id.in_(org_project_ids))

    all_findings = query.all()

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": len(all_findings),
    }

    for f in all_findings:
        if f.severity in summary:
            summary[f.severity] += 1

    return summary