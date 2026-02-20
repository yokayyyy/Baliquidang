from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import re

app = Flask(__name__)

# -----------------------
# Configuration
# -----------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change for production
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# -----------------------
# Database Model
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# -----------------------
# Input Validation
# -----------------------
def validate_input(data):
    errors = []
    if not data.get("username") or len(data["username"]) < 3:
        errors.append("Username must be at least 3 characters.")
    if not data.get("password") or len(data["password"]) < 8:
        errors.append("Password must be at least 8 characters.")
    return errors

# -----------------------
# Error Handling
# -----------------------
@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "An unexpected error occurred."}), 500

# -----------------------
# Registration Route
# -----------------------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        errors = validate_input(data)
        if errors:
            return jsonify({"errors": errors}), 400

        hashed_pw = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        new_user = User(username=data["username"], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201
    except Exception:
        return jsonify({"error": "Registration failed."}), 500

# -----------------------
# Login Route
# -----------------------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user = User.query.filter_by(username=data.get("username")).first()

        if user and bcrypt.check_password_hash(user.password, data.get("password")):
            token = create_access_token(identity=user.id)
            return jsonify(access_token=token), 200

        return jsonify({"error": "Invalid credentials"}), 401
    except Exception:
        return jsonify({"error": "Login failed."}), 500

# -----------------------
# Protected Route
# -----------------------
@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome user {current_user}!"})

# -----------------------
# Run App
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(ssl_context='adhoc')  # HTTPS enabled for local testing
