from flask import Flask, make_response, jsonify, render_template, session, send_file
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt, os, random
from flask_mail import Mail, Message
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
import pymysql
pymysql.install_as_MySQLdb()

import os
import shutil
import subprocess



app = Flask(__name__) # Instantiation of Flask object.
api = Api(app)        # Instantiation of Flask-RESTX object.
CORS(app)
############################
##### BEGIN: Database #####
##########################
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/space_parking"
app.config["SQLALCHEMY_DATABASE_URI"] =os.environ.get("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'WhatEverYouWant'
app.config['MAIL_SERVER'] = 'smtp.gmail.com' # mail env config
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
mail = Mail(app)
db = SQLAlchemy(app) # Instantiation of Flask-SQLAlchemy object.

class Users(db.Model):
    id          = db.Column(db.Integer(), primary_key=True, nullable=False)
    firstname   = db.Column(db.String(35), nullable=False)
    lastname    = db.Column(db.String(35), nullable=False)
    email       = db.Column(db.String(65), unique=True, nullable=False)
    password    = db.Column(db.String(123), nullable=False)
    is_verified = db.Column(db.Boolean(1),nullable=False)
    createdAt   = db.Column(db.Date)
    updatedAt   = db.Column(db.Date)
##########################
##### END: Database #####
########################

###########################
##### BEGIN: Register #####
#########################
parserReg = reqparse.RequestParser()
parserReg.add_argument('firstname', type=str, help='firstname', location='json', required=True)
parserReg.add_argument('lastname', type=str, help='lastname', location='json', required=True)
parserReg.add_argument('email', type=str, help='Email', location='json', required=True)
parserReg.add_argument('password', type=str, help='Password', location='json', required=True)
parserReg.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)

@api.route('/register')
class Regis(Resource):
    @api.expect(parserReg)
    def post(self):
        # BEGIN: Get request parameters.
        args        = parserReg.parse_args()
        firstname   = args['firstname']
        lastname    = args['lastname']
        email       = args['email']
        password    = args['password']
        rePassword  = args['re_password']
        is_verified = False
        # END: Get request parameters.

        # BEGIN: Check re_password.
        if password != rePassword:
            return {
                'messege': 'Kata sandi harus sama'
            }, 400
        # END: Check re_password.

        # BEGIN: Check email existance.
        user = db.session.execute(db.select(Users).filter_by(email=email)).first()
        if user:
            return "Email ini telah digunakan"
        # END: Check email existance.

        # BEGIN: Insert new user.
        user          = Users() # Instantiate Users object.
        user.firstname = firstname
        user.lastname = lastname
        user.email    = email
        user.password = generate_password_hash(password)
        user.is_verified = is_verified
        db.session.add(user)
        msg = Message(subject='Verification OTP',sender=os.environ.get("MAIL_USERNAME"),recipients=[user.email])
        token =  random.randrange(10000,99999)
        session['email'] = user.email
        session['token'] = str(token)
        msg.html=render_template(
        'verify_email.html', token=token)
        mail.send(msg)
        db.session.commit()
        # END: Insert new user.
        return {'messege': 'Registrasi Berhasil, Cek email anda untuk verifikasi'}, 201

#########################
##### END: Register #####
#######################

##############################
##### BEGIN: Verifikasi #####
############################
otpparser = reqparse.RequestParser()
otpparser.add_argument('otp', type=str, help='otp', location='json', required=True)
@api.route('/verifikasi')
class Verifi(Resource):
    @api.expect(otpparser)
    def post(self):
        args = otpparser.parse_args()
        otp = args['otp']
        if 'token' in session:
            sesion = session['token']
            if otp == sesion:
                email = session['email']
                user = Users.query.filter_by(email=email).first()
                user.is_verified = True
                db.session.commit()
                session.pop('token',None)
                return {'message' : 'Email berhasil diverifikasi'}
            else:
                return {'message' : 'Kode Otp Salah'}
        else:
            return {'message' : 'Kode Otp Salah'}
#########################
##### END: Verifikasi #####
#######################

###########################
##### BEGIN: Log in #####
#########################
# import base64
# parserBasic = reqparse.RequestParser()
# parserBasic.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)

parserLogIn = reqparse.RequestParser()
parserLogIn.add_argument('email', type=str, help='Email', location='json', required=True)
parserLogIn.add_argument('password', type=str, help='Password', location='json', required=True)

SECRET_KEY      = "WhatEverYouWant"
ISSUER          = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

@api.route('/login')
class Login(Resource):
    @api.expect(parserLogIn)
    def post(self):
        # args        = parserBasic.parse_args()
        # basicAuth   = args['Authorization']
        # # basicAuth is "Basic bWlyemEuYWxpbS5tQGdtYWlsLmNvbTp0aGlzSXNNeVBhc3N3b3Jk"
        # base64Str   = basicAuth[6:] # Remove first-6 digits (remove "Basic ")
        # # base64Str is "bWlyemEuYWxpbS5tQGdtYWlsLmNvbTp0aGlzSXNNeVBhc3N3b3Jk"
        # base64Bytes = base64Str.encode('ascii')
        # msgBytes    = base64.b64decode(base64Bytes)
        # pair        = msgBytes.decode('ascii')
        # # pair is mirza.alim.m@gmail.com:thisIsMyPassword
        # email, password = pair.split(':')

        # if email == password:
        #     return {
        #         'email': email, 
        #         'password': password 
        #     }

        # BEGIN: Get request parameters.
        argss        = parserLogIn.parse_args()
        email       = argss['email']
        password    = argss['password']
        # END: Get request parameters.

        if not email or not password:
            return {
                'message': 'Silakan isi email dan kata sandi Anda'
            }, 400

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if not user:
            return {
                'message': 'Email atau kata sandi salah'
            }, 400
        else:
            user = user[0] # Unpack the array.
        # END: Check email existance.

        # BEGIN: Check password hash.
        if check_password_hash(user.password, password):
            payload = {
                'user_id': user.id,
                'email': user.email,
                'aud': AUDIENCE_MOBILE, # AUDIENCE_WEB
                'iss': ISSUER,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours = 8)
            }
            token = jwt.encode(payload, SECRET_KEY)
            return {'message' : 'Login Berhasil',
                    'token': token,
                   }, 200
        else:
            return {
                'message': 'Email atau password salah'
            }, 400
        # END: Check password hash.
def decodetoken(jwtToken):
    decode_result = jwt.decode(
               jwtToken,
               SECRET_KEY,
               audience = [AUDIENCE_MOBILE],
			   issuer = ISSUER,
			   algorithms = ['HS256'],
			   options = {"require":["aud", "iss", "iat", "exp"]}
            )
    return decode_result
#########################
##### END: Log in #####
#######################

#########################
##### BEGIN: Upload Video #####
#######################

ALLOWED_EXTENSIONS = {'3gp', 'mkv', 'avi', 'mp4'}
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

detectParser = api.parser()
detectParser.add_argument('video', location='files', type=FileStorage, required=True)
@api.route('/detect')
class Detect(Resource):
    @api.expect(detectParser)
    def post(self):
        args = detectParser.parse_args()
        video = args['video']
        if video and allowed_file(video.filename):
            filename = secure_filename(video.filename)
            video.save(os.path.join("./video", filename))
            subprocess.run(['python', 'detect.py', '--source', f'./video/{filename}', '--weights', 'best.pt', '--name', f'{filename}'])
            print('success predict')
            os.remove(f'./video/{filename}')
            print('success remove')
            return send_file(os.path.join(f"./runs/detect/{filename}", filename), mimetype='video/mp4', as_attachment=True, download_name=filename)
        else:
            return {'message' : 'invalid file extension'},400


#########################
##### END: Upload Video #####
#######################

####################################
##### BEGIN: Bearer/Token Auth ####
##################################
authParser = reqparse.RequestParser()
authParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)

@api.route('/detail-user')
class DetailUser(Resource):
       #view user detail
       @api.expect(authParser)
       def get(self):
        args = authParser.parse_args()
        bearerAuth  = args['Authorization']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user =  db.session.execute(db.select(Users).filter_by(email=token['email'])).first()
            user = user[0]
            data = {
                'firstname' : user.firstname,
                'lastname' : user.lastname,
                'email' : user.email
            }
        except:
            return {
                'message' : 'Token Tidak valid, Silahkan Login Terlebih Dahulu'
            }, 401

        return data, 200
##################################
##### END: Bearer/Token Auth ####
################################

#################################
##### BEGIN: Edit Password #####
###############################
editPasswordParser =  reqparse.RequestParser()
editPasswordParser.add_argument('current_password', type=str, help='current_password',location='json', required=True)
editPasswordParser.add_argument('new_password', type=str, help='new_password',location='json', required=True)
@api.route('/edit-password')
class Password(Resource):
    @api.expect(authParser, editPasswordParser)
    def put(self):
        args = editPasswordParser.parse_args()
        argss = authParser.parse_args()
        bearerAuth  = argss['Authorization']
        cu_password = args['current_password']
        newpassword = args['new_password']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = Users.query.filter_by(id=token.get('user_id')).first()
            if check_password_hash(user.password, cu_password):
                user.password = generate_password_hash(newpassword)
                db.session.commit()
            else:
                return {'message' : 'Password Lama Salah'},400
        except:
            return {
                'message' : 'Token Tidak valid, Silahkan Login Terlebih Dahulu'
            }, 401
        return {'message' : 'Password Berhasil Diubah'}, 200
##################################
##### END: Edit Password ####
################################

#############################
##### BEGIN: Edit user #####
###########################
editParser = reqparse.RequestParser()
editParser.add_argument('firstname', type=str, help='Firstname', location='json', required=True)
editParser.add_argument('lastname', type=str, help='Lastname', location='json', required=True)
editParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)
@api.route('/edit-user')
class EditUser(Resource):
       @api.expect(editParser)
       def put(self):
        args = editParser.parse_args()
        bearerAuth  = args['Authorization']
        firstname = args['firstname']
        lastname = args['lastname']
        datenow =  datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = Users.query.filter_by(email=token.get('email')).first()
            user.firstname = firstname
            user.lastname = lastname
            user.updatedAt = datenow
            db.session.commit()
        except:
            return {
                'message' : 'Token Tidak valid, Silahkan Login Terlebih Dahulu'
            }, 401
        return {'message' : 'Update Users Berhasil'}, 200
################################
##### END: Edit user ####
################################

@app.route("/realtime")
def hello_world():
    return render_template('index.html')

@app.route("/opencam", methods=['GET'])
def opencam():
    print("here")
    subprocess.run(['python', 'detect.py', '--source', '0', '--weights', 'best.pt'])
    return "done"


if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)