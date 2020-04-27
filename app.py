from flask import Flask, request, jsonify, make_response, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer,String, Float, Boolean
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
import requests
from functools import wraps

app= Flask(__name__)

app.config['SECRET_KEY']='secret-key'
basedir = os.path.abspath(os.path.dirname(__file__)) #Where to store the file for the db (same folder as the running application)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir,'bookings.db') #initalized db
app.config['MAIL_SERVER']='smtp.mailtrap.io'

app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'ea1b2115a85da6'
app.config['MAIL_PASSWORD'] = 'f4639f2ee2cb85'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail=Mail(app)
s = URLSafeTimedSerializer('SECRET_KEY')
db=SQLAlchemy(app)
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

@app.cli.command('dbSeed')
def db_seed():
    hashed_password=generate_password_hash('password', method='sha256')
    testUser=Admin(name='Dr.AdminUser',
                             password=hashed_password,
                             public_id=str(uuid.uuid4()),
                             email='doctor@doctor.com',
                             admin=True)
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')

class Admin(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50), unique=True)
    name=Column(String(50))
    password=Column(String(80))
    email=Column(String(50), unique=True)
    admin=Column(Boolean)
class User(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50), unique=True)
    firstName=Column(String(50))
    lastName=Column(String(50))
    email=Column(String(50), unique=True)
    healthCard=Column(String(10))
    phoneNumber=Column(Integer)
    password=Column(String(50))
    confirmedEmail=Column(Boolean)
    confirmedOn=Column(String())
    admin=db.Column(Boolean)
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'Bearer' in request.headers:
            token=request.headers['Bearer']
        if not token:
            return jsonify(message='Token is missing'),401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify(message='Token is invalid'),401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods =['POST'])
def create_user():
        data=request.get_json()
        email=data['email']
        test=User.query.filter_by(email=email).first()

        if test:
             return jsonify(message="User already exists"),409
        else:
             hashed_password=generate_password_hash(data['password'], method='sha256')
             new_user=User(public_id=str(uuid.uuid4()),
                             firstName=data['firstName'],
                             lastName=data['lastName'],
                             email=data['email'],
                             healthCard=data['healthCard'],
                             phoneNumber=data['phoneNumber'],
                             password=hashed_password,
                             admin=False,
                             confirmedEmail=False,
                             confirmedOn=None)

        email = data['email']
        token = s.dumps(email, salt='email-confirm')

        msg = Message('Confirm Email', sender='bookingapp@booking.com', recipients=[email])

        link = url_for('confirm_email', token=token, _external=True)

        msg.body = 'Your link is {}'.format(link)

        mail.send(msg)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message='User has been created'),201

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return jsonify(message='Invalid token')
    user=User.query.filter_by(email=email).first()
    if user.confirmedEmail:
        return jsonify(message='Email already confirmed')
    else:
        user.confirmedEmail= True
        user.confirmedOn = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        return jsonify(message='Email confirmed')











if __name__ =='__main__':
    app.run(debug=True)

