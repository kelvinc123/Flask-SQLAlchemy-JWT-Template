from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt
)
from werkzeug.security import safe_str_cmp
from models.user import UserModel
from blacklist import BLACKLIST

_user_parser = reqparse.RequestParser()
_user_parser.add_argument(
    'username',
    type=str,
    required=True,
    help="Username field (can't blank)"
)
_user_parser.add_argument(
    'password',
    type=str,
    required=True,
    help="Username field (can't blank)"
)

class UserRegister(Resource):

    def post(self):

        data = _user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': "A user with that username already exists"}, 400

        user = UserModel(**data)
        user.save_to_db()

        return {"message": "User created successfully"}, 201

class User(Resource):

    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found!'}, 404

        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found!'}, 404
        
        user.delete_from_db()

        return {'message': 'User deleted'}, 200

class UserLogin(Resource):
    
    @classmethod
    def post(cls):
        # get date from db
        data = _user_parser.parse_args()

        # find user in db
        user = UserModel.find_by_username(data['username'])

        # check password
        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)  # so user can tell who they are, we need to store some data in JWT that could idenfity the user. Argument fresh is for token refreshing, we now make a fresh token
            refresh_token = create_refresh_token(user.id)

            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200

        return {
            'message': 'Invalid Credentials'
        }, 401

class UserLogout(Resource):
    @jwt_required()  # needs to login in order to logout
    def post(self):
        print(get_jwt())
        # Only blacklist the current access token, so that the user needs to log in again to get the new access token
        jti = get_jwt()['jti']  # jti stands for jwt id which is a unique identifier for JWT
        BLACKLIST.add(jti)
        return {'message': 'Successfully logged out'}, 200

class TokenRefresh(Resource):
    @jwt_required(refresh=True)  # refresh token required, defined from UserLogin
    def post(self):
        # From here, the refresh token is availale

        current_user = get_jwt_identity()  # contains user id
        new_token = create_access_token(identity=current_user, fresh=False)  # create access token that is not fresh, if the user saves the refresh token and gives us back, the user is less secure (login some times ago)
        return {
            'access_token': new_token
        }, 200