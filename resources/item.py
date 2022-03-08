from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from models.item import ItemModel


class Item(Resource):

    # Belong to class, not on a particular item resource
    parser = reqparse.RequestParser()
    parser.add_argument('price',
        type=float,
        required=True,  # no request without price
        help="This field cannot be left blank"
    )  # arg price must be given in the body json payload

    parser.add_argument('store_id',
        type=int,
        required=True,  # no request without price
        help="Every item needs a store id"
    )

    @jwt_required()
    def get(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {'message': 'Item not found!'}, 404

    @jwt_required(fresh=True)  # fresh token only
    def post(self, name):
        if ItemModel.find_by_name(name):
            return {'message': f"An item with name '{name}' already exists"}, 400

        data = Item.parser.parse_args()

        item = ItemModel(name, **data)

        try:
            item.save_to_db()
        except:
            return {'message': 'An error ocurred inserting the item.'}, 500  # internal server error

        return item.json(), 201

    @jwt_required()
    def delete(self, name):
        claims = get_jwt()  # extracted any claims attached to JWT (is_admin -> see app.py for additional claims loader)
        if not claims ['is_admin']:
            return {'message': 'Admin privilege required'}, 401
        item = ItemModel.find_by_name(name)

        if item:
            item.delete_from_db()
            return {'message': 'Item deleted'}, 200

        return {'message': 'Item not found'}, 404

    def put(self, name):
        data = Item.parser.parse_args()

        item = ItemModel.find_by_name(name)

        if item is None:
            item = ItemModel(name, **data)
        else:
            item.price = data['price']

        item.save_to_db()

        return item.json()


class ItemList(Resource):

    @jwt_required(optional=True)
    def get(self):
        user_id = get_jwt_identity()  # gives us whatever we saved in access token as identity, in this case: user id (could be none since jwt is optional: user not login or not send auth token)

        items = [x.json() for x in ItemModel.find_all()]
        if user_id:
            return {'items': items}
        return {
            'items': [item['name'] for item in items],
            'message': 'More data available if you log in.'
        }
