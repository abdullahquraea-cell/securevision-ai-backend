from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func

from app.database import Base


class User(Base):

    __tablename__ = "users"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    username = Column(
        String(50),
        unique=True,
        nullable=False
    )


    email = Column(
        String(100),
        unique=True,
        nullable=False
    )


    password_hash = Column(
        String(255),
        nullable=True  # nullable لأن مستخدمي Firebase ليس لديهم password_hash
    )


    # Firebase UID — يُملأ عند تسجيل دخول مستخدم عبر Firebase
    firebase_uid = Column(
        String(128),
        unique=True,
        nullable=True,
        index=True
    )


    role = Column(

        String(50),
        default="user"


    )

    plan = Column(String, default="free")
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)
    organization_id = Column(Integer, nullable=True)
    org_role = Column(String, default="owner")   # owner / admin / member



    is_active = Column(
        Boolean,
        default=True
    )


    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )