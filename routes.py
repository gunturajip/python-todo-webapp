from config import app, db, jwt
from flask import jsonify, redirect, render_template, request, make_response, url_for, session
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, EmailField, BooleanField, validators
from models.user import User
from models.todo import Todo
from models.token_blocklist import TokenBlocklist

class RegisterForm(FlaskForm):
    email = EmailField('email', [validators.InputRequired(), validators.Email()])
    username = StringField('username', [validators.InputRequired()])
    password = StringField('password', [validators.InputRequired()])

class LoginForm(FlaskForm):
    email = EmailField('email', [validators.InputRequired(), validators.Email()])
    password = StringField('password', [validators.InputRequired()])

class LogoutForm(FlaskForm):
    csrf_token = StringField('csrf_token', [validators.InputRequired()])

class TodoForm(FlaskForm):
    title = StringField('title', [validators.InputRequired()])
    description = StringField('description', [validators.InputRequired()])
    completed = BooleanField('completed')

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form = RegisterForm(request.form)
        if form.validate():
            password = form.password.data
            hashed_password = generate_password_hash(password).decode('utf-8')
            user = User(email=form.email.data, username=form.username.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            return render_template('login.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        form = LoginForm(request.form)
        if form.validate():
            user = User.query.filter_by(email=form.email.data).first()
            if not user or not check_password_hash(user.password, form.password.data):
                return redirect(url_for('login'))
            acces_token = create_access_token(identity=user.id)
            response = make_response(redirect(url_for('get_todos')))
            set_access_cookies(response, acces_token)
            return response
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    form = LogoutForm(request.form)
    if form.validate():
        csrf_token = form.csrf_token.data
        try:
            validate_csrf(csrf_token, secret_key=app.secret_key)
        except:
            return 'Invalid CSRF token', 400
        session.clear()
        response = make_response(redirect(url_for('login')))
        unset_jwt_cookies(response)
        response.delete_cookie('csrf_access_token')
        return response
    return render_template('todo.html')

@app.route('/todo', methods=['GET'])
@jwt_required()
def get_todos():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    todos = user.todos
    return render_template('todo.html', todos=todos)

@app.route('/todo', methods=['POST'])
@jwt_required()
def add_todo():
    # validate_csrf()
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    form = TodoForm(request.form)
    if form.validate():
        todo = Todo(title=form.title.data, description=form.description.data, user_id=user.id)
        db.session.add(todo)
        db.session.commit()
        return jsonify({'status': 201, 'message': 'successfully created a new todo'}), 201
    else:
        return jsonify({'status': 400, 'message': 'failed to create a new todo', 'error': form.errors}), 400

@app.route('/todo/<int:todo_id>', methods=['GET'])
@jwt_required()
def get_todo(todo_id):
    user_id = get_jwt_identity()
    todo = Todo.query.get(todo_id)
    if todo:
        if todo.user_id != user_id:
            return jsonify({'status': 401, 'message': 'you are not allowed to access this todo'}), 401
        return jsonify({'status': 200, 'message': 'successfully get current todo', 'data': todo}), 200
    else:
        return jsonify({'status': 404, 'message': 'current todo doesn\'t exist'}), 404

@app.route('/todo/<int:todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    # validate_csrf()
    user_id = get_jwt_identity()
    todo = Todo.query.get(todo_id)
    if todo:
        if todo.user_id != user_id:
            return jsonify({'status': 401, 'message': 'you are not allowed to access this todo'}), 401
        form = TodoForm(request.form)
        if form.validate():
            todo.title = form.title.data
            todo.description = form.description.data
            todo.completed = form.completed.data if form.completed.data else False
            db.session.commit()
            return jsonify({'status': 200, 'message': 'successfully updated current todo'}), 200
        else:
            return jsonify({'status': 400, 'message': 'failed to update current todo', 'error': form.errors}), 400
    else:
        return jsonify({'status': 404, 'message': 'current todo doesn\'t exist'}), 404

@app.route('/todo/<int:todo_id>/completed', methods=['POST'])
@jwt_required()
def mark_complete(todo_id):
    user_id = get_jwt_identity()
    todo = Todo.query.get(todo_id)
    if todo:
        if todo.user_id != user_id:
            return jsonify({'status': 401, 'message': 'you are not allowed to access this todo'}), 401
        todo.completed = True
        db.session.commit()
        return jsonify({'status': 200, 'message': 'successfully marked todo as completed'}), 200
    else:
        return jsonify({'status': 404, 'message': 'current todo doesn\'t exist'}), 404

@app.route('/todo/<int:todo_id>/uncompeted', methods=['POST'])
@jwt_required()
def mark_uncomplete(todo_id):
    user_id = get_jwt_identity()
    todo = Todo.query.get(todo_id)
    if todo:
        if todo.user_id != user_id:
            return jsonify({'status': 401, 'message': 'you are not allowed to access this todo'}), 401
        todo.completed = False
        db.session.commit()
        return jsonify({'status': 200, 'message': 'successfully marked todo as uncompleted'}), 200
    else:
        return jsonify({'status': 404, 'message': 'current todo doesn\'t exist'}), 404

@app.route('/todo/<int:todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    user_id = get_jwt_identity()
    todo = Todo.query.get(todo_id)
    if todo:
        if todo.user_id != user_id:
            return jsonify({'status': 401, 'message': 'you are not allowed to access this todo'}), 401
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'status': 200, 'message': 'successfully deleted current todo'}), 200
    else:
        return jsonify({'status': 404, 'message': 'current todo doesn\'t exist'}), 404