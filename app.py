import bcrypt
from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required
from database import db
from models.user import User

app = Flask(__name__)
login_manager = LoginManager()

app.config["SECRET_KEY"] = "my_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    user_payload = request.json()

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

if __name__ == "__main__":
    app.run(debug=True)
