from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.project import Project
from app.activity_log import log_activity

from app.schemas.project import (
    ProjectCreate,
    ProjectResponse
)

from app.routers.auth import get_current_user


router = APIRouter(
    prefix="/projects",
    tags=["Projects"]
)


# ==========================
# List Projects
# ==========================

@router.get("", response_model=list[ProjectResponse])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    query = db.query(Project)

    # مدير المنصّة (role=admin) يرى كل شيء
    # بقية المستخدمين يرون مشاريع مؤسستهم فقط (مشاركة داخل الفريق)
    if current_user.role != "admin":
        query = query.filter(
            Project.organization_id == current_user.organization_id
        )

    return query.order_by(Project.id.desc()).all()


# ==========================
# Create Project
# ==========================

@router.post("", response_model=ProjectResponse)
def create_project(
    data: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    if not data.name.strip():
        raise HTTPException(
            status_code=400,
            detail="Project name is required"
        )

    new_project = Project(
        name=data.name.strip(),
        description=data.description,
        project_type=data.project_type,
        target=data.target,
        owner_id=current_user.id,
        organization_id=current_user.organization_id
    )

    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    log_activity(
        db, current_user.id, current_user.username,
        "create_project", f"إنشاء مشروع: {new_project.name}"
    )

    return new_project


# # ==========================
# Delete Project
# ==========================

@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from sqlalchemy import text

    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    is_platform_admin = current_user.role == "admin"
    same_org = project.organization_id == current_user.organization_id
    is_org_manager = getattr(current_user, "org_role", "member") in ("owner", "admin")
    is_project_owner = project.owner_id == current_user.id

    allowed = is_platform_admin or (same_org and (is_project_owner or is_org_manager))

    if not allowed:
        raise HTTPException(
            status_code=403,
            detail="Not allowed to delete this project"
        )

    project_name = project.name

    # دالّة مساعدة: تُنفّذ DELETE مع commit مستقلّ لكلّ عملية
    def safe_delete(sql, params):
        try:
            db.execute(text(sql), params)
            db.commit()
        except Exception:
            db.rollback()

    # 1) حذف الـ findings عبر ربطها بفحوص المشروع (findings لا تحمل project_id مباشرة)
    safe_delete(
        "DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE project_id = :pid)",
        {"pid": project_id},
    )

    # 2) حذف بقيّة الجداول التي قد تحمل project_id مباشرة
    for tbl in ("ai_analyses", "reports", "scans"):
        safe_delete(
            f"DELETE FROM {tbl} WHERE project_id = :pid",
            {"pid": project_id},
        )

    # 3) حذف المشروع نفسه
    try:
        db.delete(project)
        db.commit()

        log_activity(
            db, current_user.id, current_user.username,
            "delete_project", f"حذف مشروع: {project_name}"
        )

        return {"message": "Project deleted"}

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"فشل الحذف: {str(e)[:200]}"
        )