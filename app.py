from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from flask import request, jsonify
from flask_migrate import Migrate
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
cipher_suite = Fernet(Fernet.generate_key())

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(500), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    data = db.Column(db.Text, nullable=True)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class DashboardForm(FlaskForm):
    app_name = StringField('Application Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()

@app.route('/')
def home():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    username = request.form.get('username')

    if db.session.query(User).filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password, data='{}')
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    form = DashboardForm()
    user = User.query.filter_by(username=form.username.data).first()

    if user is None:
        flash('User not found!', 'danger')
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        encrypted_data = user.data or ''  # Handle the case where user.data is None
        decrypted_data = decrypt_data(encrypted_data)
        data_dict = eval(decrypted_data) if decrypted_data else {}
        app_name = form.app_name.data
        data_dict[app_name] = {'username': form.username.data, 'password': encrypt_data(form.password.data)}
        user.data = encrypt_data(str(data_dict))
        db.session.commit()
        flash(f'Data for {app_name} saved!', 'success')

    return render_template('dashboard.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)