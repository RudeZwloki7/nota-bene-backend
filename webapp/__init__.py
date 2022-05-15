import os
from flask import Flask
from webapp.db.db_client import DBClient
from flask_cors import CORS
from flask.json import JSONEncoder
from datetime import date, time

class MyJSONEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, date):
            return o.isoformat()
        if isinstance(o, time):
            return o.isoformat()

        return super().default(o)

class MyFlask(Flask):
    json_encoder = MyJSONEncoder

app = MyFlask(__name__)
app.config['SECRET_KEY'] = 'nota-bene_2022'
CORS(app, resources={r"*": {"origins": "*"}})

db = DBClient()
db.connect()

import webapp.routes
