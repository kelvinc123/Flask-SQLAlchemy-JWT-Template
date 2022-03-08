from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import UserRegister, User, UserLogin, UserLogout, TokenRefresh
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blacklist import BLACKLIST
from db import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'  # can be mysql, postgresql, etc
app.config['PROPAGATE_EXCEPTIONS'] = True  # Let the exception returned to user
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # turn of extension tracker
# for flask but not turn of sqlalchemy tracker
app.config['JWT_BLACKLIST_ENABLED'] = True  # For enable blacklist (see blacklist.py) by default it's disabled
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']  # enable blacklist for both token

app.secret_key = 'anystringhere'  # required for JWT token or app.config['JWT_SECRET_KEY']
api = Api(app)

@app.before_first_request  # Always run before first request
def create_table():
    # Create tables for models that are imported
    db.create_all()

jwt = JWTManager(app)  # doesn't create /auth, logic's in UserLogin Resource

@jwt.additional_claims_loader  # the function must has one arg called identity. Everytime we create new access token jwt, run this function to see if we should add any extra data to the JWT
def add_claims_to_jwt(identity):
    # Since we pass identity=user.id on our user resource, the identity arg will have value user id
    if identity == 1:  # can use db instead of hard code this
        return {'is_admin': True}
    return {'is_admin': False}

@jwt.token_in_blocklist_loader  # returns true if token is in blacklist
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    # we can access any data in decrypted_token arg such as user id (see the creation of access token), but also when token is created, expired, etc
    return jwt_payload['jti'] in BLACKLIST  # contains the value that we set in access token (note: this field is available from JWT). If True, go to revoked_token_loader


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):  # if token has expired, run this function
    return jsonify({
        'description': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader  # if the token is not JWT (just a random strings)
def invalid_token_callback(error):
    return jsonify({
        'description': 'Signature vericiation failed',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader  # didn't send JWT token
def missing_token_callback(error):
    return jsonify({
        'description': 'Request does not contain an access token',
        'error': 'authorization_required'
    }), 401

@jwt.needs_fresh_token_loader  # Called when user send non fresh token on our endpoint that requires fresh token (Item post)
def token_not_fresh_callback(jwt_header, jwt_payload):
    return jsonify({
        'description': 'The token is not fresh',
        'error': 'fresh_token_required'
    }), 401

@jwt.revoked_token_loader  # Makes token no longer valid -> for loggout user 
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
            'description': 'The token has been revoked',
            'error': 'token_revoked'
        }), 401

api.add_resource(Store, '/store/<string:name>')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(StoreList, '/stores')
api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(TokenRefresh, '/refresh')


if __name__ == "__main__":
    db.init_app(app)
    app.run(port=5000, debug=True)
