#!/usr/bin/env python3

from flask import request, session, g
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import select
from marshmallow import Schema, fields, validates, ValidationError, pre_load
from marshmallow.validate import Length

from config import app, db, api
from models import User, Recipe

#! Schema's Marshmallow
class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(
        required=True, validate=Length(min=1), metadata={"description": "The unique username of the user"}
    )
    password = fields.Str(
        load_only=True,
        required=True,
        metadata={"description": "The password of the user"},
    )
    bio = fields.Str(metadata={"description": "The biography of the user"})
    image_url = fields.Str(metadata={"description": "The URL of the user's image"})

    @validates("username")
    def validate_username(self, username):
        if len(username) < 2:
            raise ValidationError("Username must contain at least two characters")

    @pre_load
    def strip_strings(self, data, **kwargs):
        extra_data = kwargs.get('extra_data')
        print(f"Extra data: {extra_data}")
        #! example use of kwags:
        #! user_schema.load(data, extra_data="extra")
        #! can do something with this like logging or tracking things
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = value.strip()
        return data

class RecipeSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(
        required=True, metadata={"description": "The title of the recipe"}
    )
    instructions = fields.Str(
        required=True,
        validate=Length(min=50, error="Instructions must be at least 50 characters long"),
        metadata={"description": "The instructions for the recipe"},
    )
    minutes_to_complete = fields.Int(
        required=True,
        metadata={"description": "The time it takes to complete the recipe"},
    )
    user_id = fields.Int(
        metadata={"description": "The ID of the user who created the recipe"}
    )

    @validates('title')
    def validate_title(self, title):
        user_id = session.get("user_id")
        if user_id is not None:
            existing_recipe = Recipe.query.filter_by(title=title, user_id=user_id).first()
            if existing_recipe is not None:
                raise ValidationError('A recipe with this title already exists.')


#! helpers
def execute_query(query):
    return db.session.execute(query).scalars()

def get_all(model):
    # return db.session.execute(select(model)).scalars().all()
    return execute_query(select(model)).all()

def get_instance_by_id(model, id):
    return db.session.get(model, id)

def get_one_by_condition(model, condition):
    # stmt = select(model).where(condition)
    # result = db.session.execute(stmt)
    # return result.scalars().first()
    return execute_query(select(model).where(condition)).first()

def get_all_by_condition(model, condition):
    # stmt = select(model).where(condition)
    # result = db.session.execute(stmt)
    # return result.scalars().all()
    return execute_query(select(model).where(condition)).all()

#! before request - verify session login
@app.before_request
def load_logged_in_user():
    # user_id = session.get("user_id")
    # if user_id is None:
    #     g.user = None
    # else:
    #     g.user = get_instance_by_id(User, user_id)

    path_dict = {"userbyid": User, "recipebyid": Recipe}

    # If the current request's endpoint is in the dictionary
    if request.endpoint in path_dict:
        # Get the ID from the request's view arguments
        id = request.view_args.get("id")

        # Get the record from the database
        record = db.session.get(path_dict.get(request.endpoint), id)

        # Determine the attribute name to set on `g`
        key_name = request.endpoint.replace("byid", "")

        # Set the attribute on `g`
        setattr(g, key_name, record)

    # If the user is logged in
    user_id = session.get("user_id")
    if user_id is not None:
        # Get the user from the database and set it on `g`
        g.user = get_instance_by_id(User, user_id)
    else:
        g.user = None

# Base class for CRUD resource classes
class BaseResource(Resource):
    model = None
    schema = None

    def get(self, id=None, condition=None):
        try:
            if id is None and condition is None:
                instances = get_all(self.model)
                return (
                    self.schema.dump(instances, many=True),
                    200,
                )  # Use the schema to serialize the instances
            elif condition is not None:
                instances = get_all_by_condition(self.model, condition)
                return (
                    self.schema.dump(instances, many=True),
                    200,
                )  # Use the schema to serialize the instances
            else:
                instance = get_instance_by_id(self.model, id)
                if instance is None:
                    return {"errors": f"{self.model.__name__} not found"}, 404
                return (
                    self.schema.dump(instance),
                    200,
                )  # Use the schema to serialize the instance
        except SQLAlchemyError as e:
            db.session.rollback()
            return {"errors": str(e)}, 500

    def delete(self, id):
        try:
            instance = get_instance_by_id(self.model, id)
            db.session.delete(instance)
            db.session.commit()
            return "", 204
        except SQLAlchemyError as e:
            db.session.rollback()
            return {"errors": str(e)}, 500

    def post(self):
        try:
            data = self.schema.load(
                request.json
            )  # Use the schema to deserialize the request data via load
            instance = self.model(**data)
            db.session.add(instance)
            db.session.commit()
            return (
                self.schema.dump(instance),
                201,
            )  # Use the schema to serialize the instance
        except ValidationError as e:
            return {"message": str(e)}, 422
        except IntegrityError:
            db.session.rollback()
            return {"message": "Invalid data"}, 422

    def patch(self, id):
        try:
            data = request.json
            data = self.schema.load(
                data
            )  # Use the schema to deserialize the request data
            instance = get_instance_by_id(self.model, id)
            for key, value in data.items():
                setattr(instance, key, value)
            db.session.commit()
            return (
                self.schema.dump(instance),
                200,
            )  # Use the schema to serialize the instance
        except ValidationError as e:
            return {"message": str(e)}, 422
        except IntegrityError:
            db.session.rollback()
            return {"message": "Invalid data"}, 422

class Signup(Resource):
    model = User
    schema = UserSchema()

    def post(self):
        data = request.json
        if not data or "username" not in data or "password" not in data:
            return {"message": "Missing 'username' or 'password' in request data"}, 422
        data = self.schema.load(data)
        if get_one_by_condition(User, User.username == data["username"]) is not None:
            return {"message": "User already exists"}, 422
        password = data.pop("password")
        user = User(**data)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()
        # Log the user in
        session["user_id"] = user.id
        session["username"] = user.username
        g.user = user

        return self.schema.dump(user), 201
class CheckSession(Resource):

    def get(self):
        if (user_id := session.get("user_id")) is None:
            return {"message": "Unauthorized"}, 401
        user = get_instance_by_id(User, user_id)
        if user is None:
            return {"message": "Unauthorized"}, 401
        return {
            "id": user.id,
            "username": user.username,
            "bio": user.bio,
            "image_url": user.image_url,
        }, 200

class Login(Resource):
    model = User
    schema = UserSchema()

    def post(self):
        data = request.json
        if not data or not data.get("username") or not data.get("password"):
            return {"message": "Missing 'username' or 'password' in request data"}, 400
        data = self.schema.load(data) 
        username = data.get("username")
        password = data.get("password")
        user = get_one_by_condition(User, User.username == username)
        if user is None or not user.authenticate(password):
            return {"message": "Invalid credentials"}, 401
        session["user_id"] = user.id
        session["username"] = user.username
        g.user = user
        return {"id": user.id, "username": user.username}, 200

class Logout(Resource):
    def delete(self):
        if (user_id := session.get("user_id")) is None:
            return {"message": "Unauthorized"}, 401
        session["user_id"] = None
        session["username"] = None
        return {}, 204

class RecipeIndex(BaseResource):
    model = Recipe
    schema = RecipeSchema()

    def get(self):
        # if (user_id := session.get("user_id")) is None:
        if g.user is None:
            return {"message": "Unauthorized"}, 401
        return super().get(condition=Recipe.user_id == g.user.id)

    def post(self):
        # if (_ := session.get("user_id")) is None:
        if g.user is None:
            return {"message": "Unauthorized"}, 401
        return super().post()
    
    def delete(self, id):
        if g.user is None:
            return {"message": "Unauthorized"}, 401
        return super().delete(id)

    def patch(self, id):
        if g.user is None:
            return {"message": "Unauthorized"}, 401
        return super().patch(id)


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
