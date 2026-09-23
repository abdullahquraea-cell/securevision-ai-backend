import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import (
    OAuth2PasswordRequestForm,
    OAuth2PasswordBearer
)

from jose import jwt, JWTError

from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings

from app.models.user import User
from app.models.organization import Organization
from app.activity_log import log_activity
from app.email_utils import send_verification_email

from datetime import datetime, timedelta
from pydantic import BaseModel
from app.email_utils import send_reset_email

from app.schemas.user import (
    UserCreate,
    UserResponse
)

from app.security.password import (
    hash_password,
    verify_password
)

from app.security.jwt import (
    create_access_token,
    SECRET_KEY,
    ALGORITHM
)

from app.security.ratelimit import rate_limit


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# رابط الواجهة الأمامية (تُبنى منه روابط التفعيل) — من الإعدادات (.env)
FRONTEND_URL = settings.FRONTEND_URL


def _make_verification_link(token: str) -> str:
    return f"{FRONTEND_URL}/verify/{token}"


# ==========================
# Get Current User (JWT)
# ==========================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:

    credentials_error = HTTPException(
        status_code=401,
        detail="Invalid or expired token"
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")

        if user_id is None:
            raise credentials_error

    except JWTError:
        raise credentials_error

    user = db.query(User).filter(
        User.id == int(user_id)
    ).first()

    if user is None or not user.is_active:
        raise credentials_error

    return user


# ==========================
# Register User
# ==========================

@router.post("/register")
def register(
    user: UserCreate,
    db: Session = Depends(get_db)
):

    existing_email = db.query(User).filter(
        User.email == user.email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    existing_username = db.query(User).filter(
        User.username == user.username
    ).first()

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    token = secrets.token_urlsafe(32)

    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password),
        role="analyst",
        is_verified=False,
        verification_token=token
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # إنشاء مؤسسة تلقائياً لكل حساب جديد وربط المستخدم كمالك لها
    org = Organization(
        name=f"مؤسسة {new_user.username}",
        owner_id=new_user.id,
        plan="free",
    )
    db.add(org)
    db.commit()
    db.refresh(org)

    new_user.organization_id = org.id
    new_user.org_role = "owner"
    db.commit()

    verification_link = _make_verification_link(token)
    print(f"[EMAIL VERIFICATION] {new_user.email} -> {verification_link}")

    email_sent = send_verification_email(new_user.email, verification_link)

    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role,
        "is_verified": False,
        "email_sent": email_sent,
        # نعرض الرابط فقط إذا لم يُرسل بريد فعلي (وضع التطوير)
        "verification_link": None if email_sent else verification_link,
        "message": (
            "تم إنشاء الحساب. تحقّق من بريدك الإلكتروني لتفعيل الحساب."
            if email_sent
            else "تم إنشاء الحساب. فعّل حسابك عبر الرابط أدناه."
        ),
    }


# ==========================
# Verify Email
# ==========================

@router.get("/verify/{token}")
def verify_email(
    token: str,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.verification_token == token
    ).first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="رابط تفعيل غير صالح أو مستخدَم مسبقاً"
        )

    user.is_verified = True
    user.verification_token = None
    db.commit()

    return {
        "message": "تم تأكيد بريدك الإلكتروني بنجاح ✅",
        "email": user.email
    }


# ==========================
# Resend Verification
# ==========================

@router.post("/resend")
def resend_verification(
    request: Request,
    email: str,
    db: Session = Depends(get_db)
):

    rate_limit(request, "resend", 3, 60)   # 3 محاولات/دقيقة

    user = db.query(User).filter(
        User.email == email
    ).first()

    # لا نكشف إن كان البريد موجوداً أم لا (أمان)
    if not user or user.is_verified:
        return {
            "message": "إن كان البريد مسجّلاً وغير مؤكَّد، فقد أُرسل رابط جديد."
        }

    token = secrets.token_urlsafe(32)
    user.verification_token = token
    db.commit()

    verification_link = _make_verification_link(token)
    print(f"[EMAIL VERIFICATION] {user.email} -> {verification_link}")

    email_sent = send_verification_email(user.email, verification_link)

    return {
        "message": (
            "تم إرسال رابط تفعيل جديد إلى بريدك."
            if email_sent
            else "تم إنشاء رابط تفعيل جديد."
        ),
        "verification_link": None if email_sent else verification_link,
    }


# ==========================
# Login User
# ==========================

@router.post("/login")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    rate_limit(request, "login", 5, 60)   # 5 محاولات/دقيقة لكل IP

    user = db.query(User).filter(
        (User.email == form_data.username) |
        (User.username == form_data.username)
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username/email or password"
        )

    if not verify_password(
        form_data.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username/email or password"
        )

    if not getattr(user, "is_verified", True):
        raise HTTPException(
            status_code=403,
            detail="يرجى تأكيد بريدك الإلكتروني قبل تسجيل الدخول."
        )

    access_token = create_access_token({
        "sub": str(user.id)
    })

    log_activity(
        db, user.id, user.username,
        "login", "تسجيل دخول ناجح"
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    }


# ==========================
# Current User Info
# ==========================

@router.get(
    "/me",
    response_model=UserResponse
)
def me(
    current_user: User = Depends(get_current_user)
):
    return current_user


# ==========================
# Forgot Password
# ==========================

class ForgotRequest(BaseModel):
    email: str


class ResetRequest(BaseModel):
    token: str
    new_password: str


@router.post("/forgot-password")
def forgot_password(
    payload: ForgotRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    rate_limit(request, "forgot", 3, 60)   # 3 محاولات/دقيقة

    user = db.query(User).filter(User.email == payload.email).first()

    # لا نكشف إن كان البريد مسجّلاً (أمان)
    if not user:
        return {"message": "إن كان البريد مسجّلاً، فقد أُرسل رابط استعادة."}

    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
    db.commit()

    reset_link = f"{FRONTEND_URL}/reset-password/{token}"
    print(f"[PASSWORD RESET] {user.email} -> {reset_link}")

    email_sent = send_reset_email(user.email, reset_link)

    return {
        "message": (
            "إن كان البريد مسجّلاً، فقد أُرسل رابط استعادة إلى بريدك."
            if email_sent
            else "تم إنشاء رابط استعادة."
        ),
        "reset_link": None if email_sent else reset_link,
    }


@router.post("/reset-password")
def reset_password(
    payload: ResetRequest,
    db: Session = Depends(get_db),
):
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="كلمة المرور 6 أحرف على الأقل")

    user = db.query(User).filter(User.reset_token == payload.token).first()

    if (
        not user
        or not user.reset_token_expiry
        or user.reset_token_expiry < datetime.utcnow()
    ):
        raise HTTPException(status_code=400, detail="رابط الاستعادة غير صالح أو منتهي الصلاحية")

    user.password_hash = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    db.commit()

    return {"message": "تم تعيين كلمة مرور جديدة بنجاح ✅"}