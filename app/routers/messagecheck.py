from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from app.models.user import User
from app.routers.auth import get_current_user
from app.scanner.messagecheck import analyze_message
from app.ai.analyzer import ask_assistant


router = APIRouter(
    prefix="/messagecheck",
    tags=["Message Check"]
)


class MsgIn(BaseModel):
    text: str
    use_ai: bool = False


@router.post("/analyze")
def analyze(
    data: MsgIn,
    current_user: User = Depends(get_current_user)
):
    if not data.text.strip():
        raise HTTPException(status_code=400, detail="الرسالة فارغة")

    result = analyze_message(data.text)

    # تحليل ذكي اختياري بـ Claude
    if data.use_ai:
        prompt = (
            "حلّل الرسالة التالية من ناحية أمنية: هل هي رسالة احتيال أو تصيّد "
            "أو آمنة؟ اشرح باختصار السبب وأعطِ نصيحة للمستخدم.\n\n"
            f"الرسالة:\n{data.text}"
        )
        try:
            result["ai_analysis"] = ask_assistant(prompt)
        except Exception as e:
            result["ai_analysis"] = f"تعذّر تحليل الذكاء الاصطناعي: {str(e)}"

    return result