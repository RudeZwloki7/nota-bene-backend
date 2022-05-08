import os
import sqlalchemy
from sqlalchemy import inspect
from sqlalchemy.orm import sessionmaker
from webapp.models.main import Base, Task, User
from webapp.core.utils import get_db_url


class DBClient:

    def __init__(self):
        self.engine = None
        self.connection = None
        self.SessionLocal = None

    def connect(self):

        self.engine = sqlalchemy.create_engine(get_db_url())
        self.connection = self.engine.connect()

        self.SessionLocal = sessionmaker(bind=self.connection.engine,
                                         autocommit=False,  # use autocommit on session.add
                                         expire_on_commit=True
                                         # expire model after commit (requests data from database)
                                         )

    def get_session(self):
        session = self.SessionLocal()
        return session

    def execute_query(self, query, fetch=False):
        res = self.connection.execute(query)
        if fetch:
            return res.fetchall()

    def create_table(self, tablename, recreate=None):
        if recreate and inspect(self.engine).has_table(tablename):
            self.execute_query(f'DROP TABLE IF EXISTS {tablename} CASCADE')

        if not inspect(self.engine).has_table(tablename):
            Base.metadata.tables[tablename].create(self.engine)
