from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
)

from app.database import Base


class Activity(Base):

    __tablename__ = "activities"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # من قام بالحدث
    user_id = Column(Integer)
    username = Column(String, default="")

    # نوع الحدث: login / create_project / run_scan / delete ...
    action = Column(String, nullable=False)

    # وصف تفصيلي
    details = Column(String, default="")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )