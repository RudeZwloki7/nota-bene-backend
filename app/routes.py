import jwt
import uuid
import json
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from functools import wraps
from app import app
from app import db
from flask import jsonify, make_response, request
from app.db.db_client import Task, User


@app.route('/')
def main_page():
    pass


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            with db.get_session() as session:
                current_user = session.query(User).filter(User.public_id == data['public_id']).first()
        except Exception as e:
            return jsonify({
                'message': 'Token is invalid!',
                'err': str(e)
            }), 401
        return f(current_user, *args, **kwargs)

    return decorated


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required!"'}
        )
    with db.get_session() as session:
        user = session.query(User).filter(User.email == auth.get('email')).first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=90)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token': token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password!"'}
    )


# signup route
@app.route('/register', methods=['POST'])
def register():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    with db.get_session() as session:
        user = session.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                name=name,
                email=email,
                password=generate_password_hash(password)
            )
            # insert user
            session.add(user)
            session.commit()

            return make_response('Successfully registered.', 201)
        else:
            # returns 202 if user already exists
            return make_response('User already exists. Please Log in.', 202)


@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    with db.get_session() as session:
        user = session.query(User).filter(User.public_id == current_user.public_id).first()
        return make_response(jsonify({'tasks': user.tasks}), 200)


@app.route('/create_task', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.json
    with db.get_session() as session:
        try:
            user = session.query(User).filter(User.public_id == current_user.public_id).first()
            task = Task(
                label=data.get('label'),
                content=data.get('content'),
                date_expire=data.get('date_expire'),
                datetime_expire=data.get('datetime_expire'),
            )
            session.add(task)
            user.tasks.append(task)
            session.commit()
            return make_response('Task created successfully', 201)
        except Exception:
            return make_response('Can not create this task!', 400)


@app.route('/task/<task_id>')
@token_required
def update_task(current_user, task_id):
    pass


@app.route('/task/<task_id>')
@token_required
def complete_task(current_user, task_id):
    pass


@app.route('/task/<task_id>')
@token_required
def delete_task(current_user, task_id):
    pass
