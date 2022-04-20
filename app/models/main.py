from dataclasses import dataclass
from datetime import date, datetime
from operator import index
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
import uuid
from sqlalchemy.schema import Table
from db.base import Base


class User(Base):
    public_id = Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String)
    tasks = relationship("Task")


@dataclass
class Task(Base):
    label: int
    content: str
    date_expire: date
    datetime_expire: datetime
    is_complete: bool

    label = Column(String, default="Empty label")
    content = Column(String, default="")
    date_expire = Column(Date, default=None)
    datetime_expire = Column(DateTime)
    is_complete = Column(Boolean, default=False)

    user_uid = Column(Integer, ForeignKey('user.uid'))
