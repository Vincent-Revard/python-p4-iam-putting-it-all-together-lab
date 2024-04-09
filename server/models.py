from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from sqlalchemy.sql.expression import text
from sqlalchemy import CheckConstraint


from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", back_populates="user")

    serialize_rules = "-recipes.user", "-password_hash"

    @hybrid_property
    def password_hash(self):
        raise AttributeError("password_hash is not a readable attribute")

    @password_hash.setter
    def password_hash(self, password):
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        self._password_hash = hashed_password

    def authenticate(self, password_to_check):
        return bcrypt.check_password_hash(self._password_hash, password_to_check)

    def __repr__(self):
        return f"User {self.username}, ID: {self.id}"


def get_default_user_id():
    result = db.session.execute(text("SELECT id FROM users LIMIT 1")).first()
    return result[0] if result else None


class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"

    __table_args__ = (db.CheckConstraint('length(instructions) > 50'), )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
    db.Integer, db.ForeignKey("users.id"), default=get_default_user_id)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)


    user = db.relationship("User", back_populates="recipes")

    # def to_ordered_dict(self):
    #     data = self.to_dict()
    #     ordered_data = {
    #         "id": data["id"],
    #         "user": {"id": data["user_id"]},
    #         "title": data["title"],
    #         "instructions": data["instructions"],
    #         "minutes_to_complete": data["minutes_to_complete"],
    #     }
    #     return ordered_data
    # @validates("instructions")
    # def validate_instructions(self, _, instructions):
    #     if not isinstance(instructions, str):
    #         raise TypeError("Instructions must be string")
    #     if len(instructions) < 50:
    #         raise ValueError("Instructions must be at least 50 characters long")
    #     return instructions
