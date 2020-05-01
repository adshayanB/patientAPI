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
    testUser=Doctor(name='Dr.AdminUser',
                             password=hashed_password,
                             public_id=str(uuid.uuid4()),
                             email='doctor@doctor.com',
                             admin=True,
                             clinician=True,
                             confirmedEmail=True,
                             confirmedOn=None
                             )
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')

class Doctor(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50), unique=True)
    name=Column(String(50))
    password=Column(String(80))
    email=Column(String(50), unique=True)
    admin=Column(Boolean)
    clinician=Column(Boolean)
    confirmedEmail=Column(Boolean)
    confirmedOn=Column(String())
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
        if 'x-access-tokens' in request.headers:
            token=request.headers['x-access-tokens']
        if not token:
            return jsonify(message='Token is missing'),401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=Doctor.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify(message='Token is invalid'),401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/doctor/login')
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})

    user=Doctor.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})
    if check_password_hash( user.password,auth.password):
        token=jwt.encode({'public_id': user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(token=token.decode('UTF-8'))#
    else:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})

@app.route('/doctor', methods=['POST'])
@token_required
def create_doctor(current_user):

    if not current_user.admin:
        return jsonify(message='Credentials invalid')

    data=request.get_json()
    email=data['email']
    test=User.query.filter_by(email=email).first()

    if test:
        return jsonify(message="User already exists"),409
    else:
             hashed_password=generate_password_hash(data['password'], method='sha256')
             new_doc=Doctor(public_id=str(uuid.uuid4()),
                             name=data['name'],
                             email=data['email'],
                             password=hashed_password,
                             admin=False,
                             clinician=True,
                             confirmedEmail=False,
                             confirmedOn=None)

    email = data['email']
    token = s.dumps(email, salt='email-confirm')

    msg = Message('Confirm Email', sender='bookingapp@booking.com', recipients=[email])

    link = url_for('confirm_email', token=token, _external=True)

    msg.body = 'Your link is {}'.format(link)

    mail.send(msg)
    db.session.add(new_doc)
    db.session.commit()
    return jsonify(message='Doctor has been added'),201

@app.route('/doctor', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify(message="You don't have valid credentials")
    doctors=Doctor.query.all()
    output=[]
    for doctor in doctors:
        doctor_data={}
        doctor_data['public_id']=doctor.public_id
        doctor_data['name']=doctor.name
        doctor_data['password']=doctor.password
        doctor_data['email']=doctor.email
        doctor_data['admin']=doctor.admin
        doctor_data['clinician']=doctor.clinician
        doctor_data['confirmedEmail']=doctor.confirmedEmail
        doctor_data['confirmedOn']=doctor.confirmedOn
        output.append(doctor_data)

    return jsonify(doctors=output)

@app.route('/doctor/<public_id>', methods=['GET'])
@token_required
def get_doctor(current_user,public_id):
    if not current_user.admin:
        return jsonify(message='You do not have valid credentials')
    doctor=Doctor.query.filter_by(public_id=public_id).first()
    if doctor:
        doctor_data={}
        doctor_data['public_id']=doctor.public_id
        doctor_data['name']=doctor.name
        doctor_data['password']=doctor.password
        doctor_data['email']=doctor.email
        doctor_data['admin']=doctor.admin
        doctor_data['clinician']=doctor.clinician
        doctor_data['confirmedEmail']=doctor.confirmedEmail
        doctor_data['confirmedOn']=doctor.confirmedOn

        return jsonify(doctor=doctor_data)
    else:
        return jsonify(message="Doctor does not exist")

@app.route('/doctor/<public_id>', methods=['PUT'])
@token_required
def upgrade_to_admin (current_user, public_id):
    if not current_user.admin:
        return jsonify(message="You do not have the valid credentials")
    else:
         doctor=Doctor.query.filter_by(public_id=public_id).first()
         doctor.admin=True
         db.session.commit()
         return jsonify(message="Doctor given admin credentials")


@app.route('/doctor/<public_id>', methods=['DELETE'])
@token_required
def delete_doctor(current_user,public_id):
    if not current_user.admin:
        return jsonify(message="You don't have valid credentials")
    else:
        doc=Doctor.query.filter_by(public_id=public_id).first()
        if doc:
            db.session.delete(doc)
            db.session.commit()
            return jsonify(message="Doctor deleted")
        else:
            return jsonify(message="User not found")


@app.route('/user', methods =['POST'])
@token_required
def create_user(current_user):

        if not current_user.clinician:
            return jsonify(message="You don't have valid credentials")
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
    user=Doctor.query.filter_by(email=email).first()
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

