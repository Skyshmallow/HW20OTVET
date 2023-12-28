# -*- coding: utf-8 -*-
from hashlib import sha256
from typing import Union
from uuid import uuid4

from flask import jsonify, redirect, render_template, request, url_for
from flask_jwt_extended import JWTManager, create_access_token
from flask_wtf import FlaskForm
from jwt import decode as d
from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired

from app import app
from app.models import db

app.config["JWT_SECRET_KEY"] = "super-secret-password"  # Change this!
app.config['SECRET_KEY'] = 'root'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'None'
j_w_t = JWTManager(app)


class LoginForm(FlaskForm):
  email = EmailField('Email',
                     validators=[DataRequired()],
                     render_kw={
                         'class': 'form-control',
                         'id': 'email',
                         'aria-describedby': 'emailHelp'
                     })
  pwd = PasswordField('Password',
                      validators=[DataRequired()],
                      render_kw={
                          'class': 'form-control',
                          'id': 'pwd'
                      })
  submit = SubmitField('Submit', render_kw={'class': 'btn btn-primary'})


class SignUpForm(FlaskForm):
  name = StringField('Name',
                     validators=[DataRequired()],
                     render_kw={
                         'class': 'form-control',
                         'id': 'name',
                         "placeholder": "Name",
                         'aria-describedby': 'nameHelp'
                     })
  email = EmailField('Email',
                     validators=[DataRequired()],
                     render_kw={
                         'class': 'form-control',
                         'id': 'email',
                         'aria-describedby': 'emailHelp',
                         "placeholder": "Email"
                     })
  pwd = PasswordField('Password',
                      validators=[DataRequired()],
                      render_kw={
                          'class': 'form-control',
                          'id': 'pwd'
                      })
  submit = SubmitField('Submit', render_kw={'class': 'btn btn-success'})


@app.get('/')
@app.get('/home')
def index():
  token = request.cookies.get('token', None)
  print(token)
  has_token = False
  if token is not None:
    has_token = True

  return render_template('home.html',
                         names=db.get_all_users_names(),
                         has_token=has_token)


@app.get('/login')
def get_login_page():
  login = LoginForm()
  return render_template('login.html', form=login)


@app.post('/login')
def post_login():
    email = sha256(request.form['email'].encode('utf-8')).hexdigest()
    pwd = sha256(request.form['pwd'].encode('utf-8')).hexdigest()

    def get_user(email: str, pwd: str) -> Union[dict, None]:
        for user in db.get_all_users():
            if user['email'] == email and user['password'] == pwd:
                return user
        return None

    user = get_user(email, pwd)
    if user is None:
        return jsonify({"msg": "Incorrect email or password"}), 401

    additional_claims = {"role": user['role'], "id": user['id']}
    access_token = create_access_token(user['name'],
                                        additional_claims=additional_claims)
    
    # Setting the access token in the cookies
    response = jsonify(access_token=access_token, role=user['role'])
    response.set_cookie('token', value=access_token, httponly=True, samesite='None', secure=True)
    return response


@app.get('/logout')
def logout():
  return redirect(url_for('home'))


@app.get('/signup')
def get_signup_page():
  signup = SignUpForm()
  return render_template('sign_up.html', form=signup)


@app.post('/signup')
def create_new_user():
  print(request.form)
  data = {
      'id': str(uuid4()),
      'name': str(request.form['name']),
      'role': 'user',
      'email': sha256(request.form['email'].encode('utf-8')).hexdigest(),
      'password': sha256(request.form['pwd'].encode('utf-8')).hexdigest()
  }

  db.add_user(data)
  return jsonify({"status": "success"})


@app.get('/admin')
def admin():
  token = request.cookies.get('token', None)
  if token is None:
    return render_template('access.html')
  decoded_token = d(jwt=token,
                    key="super-secret-password",
                    algorithms=["HS256"])

  if decoded_token['role'] != 'admin':
    return render_template('access.html')
  return render_template('admin.html')


@app.get('/user')
def user():
  token = request.cookies.get('token', None)
  if token is None:
    return render_template('access.html')
  decoded_token = d(jwt=token,
                    key="super-secret-password",
                    algorithms=["HS256"])

  if decoded_token['role'] != 'user':
    return render_template('access.html')
  return render_template('user.html', user=decoded_token['sub'])
