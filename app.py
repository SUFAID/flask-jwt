from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY']='sufitest123'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config['SECRET_KEY_JWT']='sufitest123'

db = SQLAlchemy(app)

#model class for User
class Users(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     public_id = db.Column(db.Integer)
     name = db.Column(db.String(50))
     password = db.Column(db.String(50))
     created_at = db.Column(db.DateTime,default=datetime.datetime.utcnow)

## decorator
def token_required(f):
	"""decorator for validate tiken"""
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'access-tokens' in request.headers:
         token = request.headers['access-tokens']

      if not token:
         return jsonify({'message': 'A valid token is missing'})

      try:
         data = jwt.decode(token, app.config["SECRET_KEY_JWT"])
         current_user = Users.query.filter_by(public_id=data['public_id']).first()
         if not current_user:
         	return jsonify({'message': "Invalid token"})

      except jwt.ExpiredSignature :
         return jsonify({'message': "Expired Token"})
      except:
         return jsonify({'message': "Invalid token"})

      return f(*args, **kwargs)
   return decorator


@app.route('/register', methods=['POST'])
def signup_user():
 data = request.get_json()

 hashed_password = generate_password_hash(data['password'], method='sha256')

 new_user = Users(public_id=str(uuid.uuid4()), name=data['username'], password=hashed_password)
 db.session.add(new_user)
 db.session.commit()
 return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():

  auth = request.authorization

  if not auth or not auth.username or not auth.password:
     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

  user = Users.query.filter_by(name=auth.username).first()

  if check_password_hash(user.password, auth.password):
     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY_JWT'])
     return jsonify({'token' : token.decode('UTF-8')})

  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/users', methods=['GET'])
@token_required
def get_all_users():
   users = Users.query.all()
   result = []

   for user in users:
       user_data = {}
       user_data['public_id'] = user.public_id
       user_data['name'] = user.name
       user_data['password'] = user.password
       user_data['created_at'] = user.created_at

       result.append(user_data)

   return jsonify({'users': result})

if  __name__ == '__main__':
     app.run(debug=True)