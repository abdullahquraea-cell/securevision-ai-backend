import traceback

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.database import get_db

from app.models.user import User
from app.models.project import Project
from app.models.finding import Finding

from app.routers.auth import get_current_user

from app.ai.analyzer import analyze_finding, ask_assistant


router = APIRouter(
    prefix="/ai",
    tags=["AI Analysis"]
)


# ==========================
# تحليل ثغرة
# ==========================

@router.post("/analyze/{finding_id}")
def analyze(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    finding = db.query(Finding).filter(
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    if current_user.role != "admin":
        project = db.query(Project).filter(
            Project.id == finding.project_id
        ).first()

        if not project or project.owner_id != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="Not allowed"
            )

    # إذا كان التحليل محفوظاً مسبقاً، أرجعه فوراً (بلا تكلفة)
    if finding.ai_analysis:
        return {
            "finding_id": finding.id,
            "analysis": finding.ai_analysis,
            "cached": True,
        }

    # وإلا، استدعِ الذكاء الاصطناعي واحفظ النتيجة
    try:
        analysis = analyze_finding(
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            location=finding.location,
        )
    except Exception as e:
        # طباعة التتبّع الكامل في نافذة uvicorn لتشخيص المشكلة
        print("\n===== AI ANALYZE ERROR (full traceback) =====")
        traceback.print_exc()
        print("=============================================\n")
        raise HTTPException(
            status_code=500,
            detail=f"فشل تحليل الذكاء الاصطناعي: {str(e)}"
        )

    # حفظ التحليل في قاعدة البيانات
    finding.ai_analysis = analysis
    db.commit()

    return {
        "finding_id": finding.id,
        "analysis": analysis,
        "cached": False,
    }


# ==========================
# المساعد الأمني
# ==========================

class AskRequest(BaseModel):
    question: str


@router.post("/ask")
def ask(
    data: AskRequest,
    current_user: User = Depends(get_current_user)
):
    if not data.question.strip():
        raise HTTPException(
            status_code=400,
            detail="السؤال فارغ"
        )

    try:
        answer = ask_assistant(data.question)
    except Exception as e:
        print("\n===== AI ASK ERROR (full traceback) =====")
        traceback.print_exc()
        print("=========================================\n")
        raise HTTPException(
            status_code=500,
            detail=f"فشل المساعد: {str(e)}"
        )

    return {"answer": answer}