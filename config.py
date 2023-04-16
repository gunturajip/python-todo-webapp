from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://'+str(os.getenv('PGUSER'))+':'+str(os.getenv('PGPASSWORD'))+'@'+str(os.getenv('PGHOST'))+':'+str(os.getenv('PGPORT'))+'/'+str(os.getenv('PGDATABASE'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
csrf = CSRFProtect(app)