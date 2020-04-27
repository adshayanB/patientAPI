from flask import Flask, request, jsonify, make_response
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
                             email='doctor@doctor.com',
                             admin=True)
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')

class Admin(db.Model):
    id=Column(Integer, primary_key=True)
    #public_id=Column(String(50), unique=True)
    name=Column(String(50))
    password=Column(String(80))
    email=Column(String(50), unique=True)
    admin=db.Column(Boolean)


if __name__ =='__main__':
    app.run(debug=True)

