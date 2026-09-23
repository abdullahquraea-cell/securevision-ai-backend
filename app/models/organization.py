from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime

from app.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, nullable=False)   # مُنشئ المؤسسة
    plan = Column(String, default="free")        # الباقة على مستوى المؤسسة
    created_at = Column(DateTime, default=datetime.utcnow)