from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from sqlalchemy.orm import Session

import stripe

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.project import Project
from app.routers.auth import get_current_user


stripe.api_key = settings.STRIPE_SECRET_KEY


router = APIRouter(prefix="/subscription", tags=["Subscription"])


PLANS = {
    "free": {
        "name": "مجاني",
        "price": 0,
        "projects": 3,
        "scans_per_month": 10,
        "ai": False,
        "features": ["3 مشاريع", "10 فحوصات شهرياً", "فحص المواقع والمنافذ", "تقارير أساسية"],
    },
    "pro": {
        "name": "احترافي",
        "price": 29,
        "projects": 25,
        "scans_per_month": -1,
        "ai": True,
        "features": [
            "25 مشروعاً", "فحوصات غير محدودة",
            "كل المحرّكات (Nuclei / SQLMap / Nmap)",
            "تحليل بالذكاء الاصطناعي", "تقارير PDF احترافية", "دعم عبر البريد",
        ],
    },
    "enterprise": {
        "name": "مؤسسات",
        "price": 99,
        "projects": -1,
        "scans_per_month": -1,
        "ai": True,
        "features": [
            "مشاريع غير محدودة", "فحوصات غير محدودة", "كل الميزات",
            "تعدد المستخدمين", "دعم أولوية 24/7", "تكامل API",
        ],
    },
}


@router.get("/plans")
def get_plans():
    return PLANS


@router.get("/me")
def my_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    plan_key = getattr(current_user, "plan", "free") or "free"
    plan = PLANS.get(plan_key, PLANS["free"])

    now = datetime.now()
    projects_count = db.query(Project).filter(Project.owner_id == current_user.id).count()

    scans_this_month = 0
    for s in db.query(Scan).filter(Scan.owner_id == current_user.id).all():
        try:
            if s.created_at.year == now.year and s.created_at.month == now.month:
                scans_this_month += 1
        except Exception:
            pass

    return {
        "plan": plan_key,
        "plan_info": plan,
        "usage": {"projects": projects_count, "scans_this_month": scans_this_month},
    }


class UpgradeRequest(BaseModel):
    plan: str


@router.post("/upgrade")
def upgrade(
    data: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.plan not in PLANS:
        raise HTTPException(status_code=400, detail="باقة غير صحيحة")

    current_user.plan = data.plan
    db.commit()

    return {"message": "تم تغيير الباقة بنجاح", "plan": data.plan}


# ==========================
# Stripe: إنشاء جلسة دفع
# ==========================

class CheckoutRequest(BaseModel):
    plan: str


class ConfirmRequest(BaseModel):
    session_id: str


@router.post("/checkout")
def create_checkout(
    payload: CheckoutRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plan = payload.plan
    if plan not in PLANS or plan == "free":
        raise HTTPException(status_code=400, detail="باقة غير صالحة للدفع")

    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="لم يتم إعداد Stripe بعد")

    info = PLANS[plan]

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": f"SecureVision — {info['name']}"},
                    "unit_amount": int(info["price"]) * 100,   # بالسنت
                    "recurring": {"interval": "month"},
                },
                "quantity": 1,
            }],
            success_url=f"{settings.FRONTEND_URL}/subscription/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{settings.FRONTEND_URL}/subscription",
            client_reference_id=str(current_user.id),
            metadata={"user_id": str(current_user.id), "plan": plan},
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"خطأ Stripe: {e}")


# ==========================
# Stripe: تأكيد الدفع وترقية الباقة
# ==========================

@router.post("/confirm")
def confirm_checkout(
    payload: ConfirmRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="لم يتم إعداد Stripe بعد")

    try:
        session = stripe.checkout.Session.retrieve(payload.session_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"جلسة غير صالحة: {e}")

    if session.payment_status != "paid":
        raise HTTPException(status_code=400, detail="لم يكتمل الدفع بعد")
    meta = session.metadata or {}
    meta_user = meta["user_id"] if "user_id" in meta else None
    meta_plan = meta["plan"] if "plan" in meta else None

    if str(meta_user) != str(current_user.id):
        raise HTTPException(status_code=403, detail="هذه الجلسة لا تخصّك")

    if meta_plan not in PLANS:
        raise HTTPException(status_code=400, detail="باقة غير معروفة")

    current_user.plan = meta_plan
    db.commit()

    return {"message": "تمت ترقية باقتك بنجاح ✅", "plan": meta_plan}