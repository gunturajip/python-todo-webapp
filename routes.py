from config import app, db
import jwt as j
from flask import redirect, render_template, request, make_response, url_for, session
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, EmailField, BooleanField, validators
from models.user import User
from models.todo import Todo

class RegisterForm(FlaskForm):
    email = EmailField('email', [validators.InputRequired(), validators.Email()])
    name = StringField('name', [validators.InputRequired()])
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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form = RegisterForm(request.form)
        if form.validate():
            password = form.password.data
            hashed_password = generate_password_hash(password).decode('utf-8')
            user = User(email=form.email.data, name=form.name.data, password=hashed_password)
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


@app.route('/todo/<action>', methods=['GET', 'POST'])
def add_todo(action):
    if request.method == 'POST':
        access_token_cookie = request.cookies.get('access_token_cookie')
        if not access_token_cookie:
            return redirect(url_for('login'))
        try:
            token = j.decode(access_token_cookie, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            user_id = token.get('sub')
        except:
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        form = TodoForm(request.form)
        if not form.validate():
            return render_template('add_edit.html')
        todo = Todo(title=form.title.data, description=form.description.data, user_id=user.id)
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for('get_todos'))
    return render_template('add_edit.html', action=action)


@app.route('/todo/<int:todo_id>', methods=['GET'])
@jwt_required()
def get_todo(todo_id):
    todo = Todo.query.get(todo_id)
    return render_template('add_edit.html', todo=todo)


@app.route('/todo/<int:todo_id>', methods=['POST'])
def update_todo(todo_id):
    access_token_cookie = request.cookies.get('access_token_cookie')
    if not access_token_cookie:
        return redirect(url_for('login'))
    try:
        token = j.decode(access_token_cookie, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    except:
        return redirect(url_for('login'))

    todo = Todo.query.get(todo_id)
    form = TodoForm(request.form)
    if not form.validate():
        return redirect(url_for('update_todo(todo.id)'))

    todo.title = form.title.data
    todo.description = form.description.data
    todo.completed = form.completed.data if form.completed.data else False
    db.session.commit()
    return redirect(url_for('get_todos'))


@app.route('/todo/<int:todo_id>/completed', methods=['GET'])
@jwt_required()
def mark_complete(todo_id):
    todo = Todo.query.get(todo_id)
    todo.completed = True
    db.session.commit()
    return redirect(url_for('get_todos'))


@app.route('/todo/<int:todo_id>/uncompleted', methods=['GET'])
@jwt_required()
def mark_uncomplete(todo_id):
    todo = Todo.query.get(todo_id)
    todo.completed = False
    db.session.commit()
    return redirect(url_for('get_todos'))


@app.route('/todo/<int:todo_id>/<action>', methods=['GET'])
def delete_todo(todo_id, action):
    access_token_cookie = request.cookies.get('access_token_cookie')
    if not access_token_cookie:
        return redirect(url_for('login'))
    try:
        token = j.decode(access_token_cookie, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    except:
        return redirect(url_for('login'))
    
    if action == 'delete':
        todo = Todo.query.get(todo_id)
        db.session.delete(todo)
        db.session.commit()
        return redirect(url_for('get_todos'))
