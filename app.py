import os
import bcrypt
from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from database import db
from models.user import User

app = Flask(__name__)
login_manager = LoginManager()

basedir = os.path.abspath(os.path.dirname(__file__))
database_path = os.path.join(basedir, "database.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path}"
app.config["SECRET_KEY"] = "my_secret_key"

db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    user_payload = request.json

    username = user_payload.get("username")
    password = user_payload.get("password")
    
    user = User.query.filter_by(username=username).first()
    valid_password = bcrypt.checkpw(str.encode(password), str.encode(user.password))
    
    if user and valid_password:
        login_user(user)
        return jsonify({"message": "User authenticated!"})

    return jsonify({"message": "Invalid credentials!"}), 400

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "User logged out!"})

@app.route("/user", methods=["POST"])
def create_user():
    user_payload = request.json

    username = user_payload.get("username")
    password = user_payload.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())

        user = User(username=username, password=hashed_password, role="user")

        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User created successfully!"})
    
    return jsonify({"message": "Invalid credentials!"}), 400

@app.route("/user/<int:user_id>", methods=["GET"])
@login_required
def load_user(user_id):
    user = User.query.get(user_id)

    if user:
        return jsonify({"username": user.name})

    return jsonify({"message": "User not found!"}), 404

@app.route("/user/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    user = User.query.get(user_id)
    user_payload = request.json
    new_password = user_payload.get("password")

    if current_user.role != 'admin':
        return jsonify({ "message": "Forbidden action!" }), 403

    if user and new_password:
        user.password = new_password
        db.session.commit()

        return jsonify({ "message": f"User {user_id} updated!" })
    
    return jsonify({"message": "User not found!"}), 404

@app.route("/user/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if current_user.role != 'admin':
        return jsonify({ "message": "Forbidden action!" }), 403

    if current_user.id == user_id:
        return jsonify({ "message": "Forbidden action!" }), 403

    if user:
        db.session.delete(user)
        db.session.commit()

    return jsonify({"message": "User not found!"}), 404

if __name__ == "__main__":
    app.run(debug=True)
