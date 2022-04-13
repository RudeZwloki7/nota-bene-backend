from operator import index
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, String
from sqlalchemy.schema import Table
from db.base import Base


class User(Base):
    email = Column(String, unique=True, nullable=False)
    password = Column(String)
    tasks = relationship("Task")


class Task(Base):
    label = Column(String, default="Empty label")
    content = Column(String, default="")
    date_expire = Column(Date)
    datetime_expire = Column(DateTime)
    is_complete = Column(Boolean, default=False)

    user_uid = Column(Integer, ForeignKey('user.uid'))
