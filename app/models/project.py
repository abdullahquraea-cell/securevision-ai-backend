from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey
)

from app.database import Base


class Project(Base):

    __tablename__ = "projects"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(String, nullable=False)

    description = Column(String, default="")

    # نوع المشروع: web / api / code / mobile / docker
    project_type = Column(String, default="web")

    # الهدف: رابط الموقع أو مسار المستودع
    target = Column(String, default="")

    status = Column(String, default="active")

    owner_id = Column(
        Integer,
        ForeignKey("users.id")
    )

    organization_id = Column(Integer, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )