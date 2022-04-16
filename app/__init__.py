import os
from flask import Flask
from db.db_client import DBClient

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nota-bene_2022'

db = DBClient()
db.connect()

import routes
