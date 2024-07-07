from flask import Flask
from flask_login import LoginManager
from database import db

app = Flask(__name__)
login_manager = LoginManager()

app.config["SECRET_KEY"] = "my_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db.init_app(app)
login_manager.init_app(app)

if __name__ == "__main__":
    app.run(debug=True)
