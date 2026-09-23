import os
import html

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.email_utils import send_email
from app.security.ratelimit import rate_limit


router = APIRouter(prefix="/contact", tags=["Contact"])


class ContactIn(BaseModel):
    name: str
    email: str = ""
    message: str


@router.post("/send")
def send_contact(data: ContactIn, request: Request):
    rate_limit(request, "contact", 5, 300)   # 5 رسائل كل 5 دقائق

    if not data.name.strip() or not data.message.strip():
        raise HTTPException(status_code=400, detail="الاسم والرسالة مطلوبان")

    admin = os.getenv("CONTACT_EMAIL") or os.getenv("SMTP_FROM") or os.getenv("SMTP_USER")
    if not admin:
        raise HTTPException(status_code=500, detail="لم يتم إعداد بريد الاستقبال")

    name = html.escape(data.name.strip())
    email = html.escape(data.email.strip())
    message = html.escape(data.message.strip())

    body = f"""
    <div style="font-family:system-ui,Arial,sans-serif;direction:rtl;max-width:560px;margin:auto">
      <h2 style="color:#1d4ed8">📩 رسالة جديدة من صفحة التواصل</h2>
      <p><b>الاسم:</b> {name}</p>
      <p><b>البريد:</b> {email or 'غير مذكور'}</p>
      <p><b>الرسالة:</b></p>
      <p style="white-space:pre-wrap;background:#f8fafc;padding:14px;border-radius:8px">{message}</p>
    </div>
    """

    ok = send_email(admin, f"تواصل من {name} - SecureVision AI", body)
    if not ok:
        raise HTTPException(status_code=500, detail="تعذّر إرسال الرسالة، حاول لاحقاً")

    return {"message": "تم إرسال رسالتك بنجاح ✅ سنتواصل معك قريباً"}