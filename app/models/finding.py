from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey
)

from app.database import Base


class Finding(Base):

    __tablename__ = "findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id")
    )

    project_id = Column(
        Integer,
        ForeignKey("projects.id")
    )

    title = Column(String, nullable=False)

    severity = Column(String, default="info")

    description = Column(Text, default="")

    location = Column(String, default="")

    recommendation = Column(Text, default="")

    ai_analysis = Column(Text, default="")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )