from datetime import datetime

from pydantic import BaseModel


class ProjectCreate(BaseModel):

    name: str

    description: str = ""

    project_type: str = "web"

    target: str = ""


class ProjectResponse(BaseModel):

    id: int

    name: str

    description: str

    project_type: str

    target: str

    status: str

    owner_id: int

    created_at: datetime

    class Config:
        from_attributes = True