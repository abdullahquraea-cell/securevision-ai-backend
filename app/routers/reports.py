from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.project import Project
from app.models.finding import Finding

from app.routers.auth import get_current_user

from app.reports.generator import generate_report


router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)


@router.get("/project/{project_id}")
def project_report(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    if (
        current_user.role != "admin"
        and project.owner_id != current_user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    findings = db.query(Finding).filter(
        Finding.project_id == project_id
    ).all()

    findings_data = [
        {
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "location": f.location,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]

    pdf = generate_report(project.name, findings_data)

    filename = f"report_project_{project_id}.pdf"

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )