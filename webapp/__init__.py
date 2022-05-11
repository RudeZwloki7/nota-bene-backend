import os
from flask import Flask
from webapp.db.db_client import DBClient
from flask_cors import CORS

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nota-bene_2022'
CORS(app, resources={r"*": {"origins": "*"}})

db = DBClient()
db.connect()

import webapp.routes
