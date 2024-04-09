#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import select, and_
from werkzeug.exceptions import BadRequest, NotFound


from config import app, db, api
from models import User, Recipe


#! helpers
def get_all(model, only=None):
    instances = db.session.execute(select(model)).scalars().all()
    if only is None:
        return [instance.to_ordered_dict() for instance in instances]
    else:
        return [instance.to_dict(only=only) for instance in instances]


def get_instance_by_id(model, id):
    if (instance := db.session.get(model, id)) is None:
        raise NotFound(description=f"{model.__name__} not found")
    return instance


def get_one_by_condition(model, condition):
    stmt = select(model).where(condition)
    result = db.session.execute(stmt)
    return result.scalars().first()

def get_all_by_condition(model, condition):
    stmt = select(model).where(condition)
    result = db.session.execute(stmt)
    return result.scalars().all()

# Base class for CRUD resource classes
class BaseResource(Resource):
    model = None
    fields = None

    def get(self, id=None, condition=None):
        try:
            if id is None and condition is None:
                return get_all(self.model, self.fields), 200
            elif condition is not None:
                instances = get_all_by_condition(self.model, condition)
                return [instance.to_dict() for instance in instances], 200
            else:
                instance = get_instance_by_id(self.model, id)
                return instance.to_dict(), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            return {"errors": str(e)}, 500

    def delete(self, id):
        instance = get_instance_by_id(self.model, id)
        db.session.delete(instance)
        db.session.commit()
        return "", 204

    def post(self):
        try:
            data = request.get_json(force=True)
            instance = self.model(**data)
            db.session.add(instance)
            db.session.commit()
            return instance.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "Invalid data"}, 422
        except ValueError as e:
            return {"message": str(e)}, 422

    def patch(self, id):
        try:
            data = request.get_json(force=True)
            instance = get_instance_by_id(self.model, id)
            for key, value in data.items():
                setattr(instance, key, value)
            db.session.commit()
            return instance.to_dict(), 200
        except IntegrityError:
            db.session.rollback()
            return {"message": "Invalid data"}, 422
        except ValueError as e:
            return {"message": str(e)}, 422


class Signup(Resource):
    model = User

    def post(self):
        data = request.get_json(force=True)
        if not data or not data.get("username") or not data.get("password"):
            return {"message": "Missing 'username' or 'password' in request data"}, 422
        username = data.get("username")
        password = data.get("password")
        bio = data.get("bio", None)
        image_url = data.get("image_url", None)
        if get_one_by_condition(User, User.username == username) is not None:
            return {"message": "User already exists"}, 422
        user = User(username=username, bio=bio, image_url=image_url)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()
        return {
            "id": user.id,
            "username": user.username,
            "bio": user.bio,
            "image_url": user.image_url,
        }, 201


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

    def post(self):
        data = request.get_json(force=True)
        if not data or not data.get("username") or not data.get("password"):
            return {"message": "Missing 'username' or 'password' in request data"}, 400
        username = data.get("username")
        password = data.get("password")
        user = get_one_by_condition(User, User.username == username)
        if user is None or not user.authenticate(password):
            return {"message": "Invalid credentials"}, 401
        session["user_id"] = user.id
        session["username"] = user.username
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
    fields = ["id", "title", "instructions", "minutes_to_complete"]

    def get(self):
        # try:
        if (user_id := session.get("user_id")) is None:
            return {"message": "Unauthorized"}, 401
        return super().get(condition=Recipe.user_id == user_id)

        #     user_recipes = (
        #         db.session.execute(select(Recipe).where(Recipe.user_id == user_id)).scalars().all()
        #     )
        #     if not user_recipes:
        #         return {"recipes": []}, 200
        #     return [recipe.to_dict() for recipe in user_recipes], 200
        # except ValueError as e:
        #     return {"message": str(e)}, 422

    def post(self):
        if (user_id := session.get("user_id")) is None:
            return {"message": "Unauthorized"}, 401
        return super().post()


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
