from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from models import db, User
import logging

app = Flask(__name__)
app.secret_key = "super-secret-key"

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)
bcrypt = Bcrypt(app)

# Logging setup
logging.basicConfig(filename='app.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')

            # Input validation
            if not username or len(username) < 3 or not password or len(password) < 8:
                return render_template('registration.html')

            # Check if user exists
            if User.query.filter_by(username=username).first():
                return render_template('registration.html')

            # Hash password & save
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            logging.info(f"New user registered: {username}")

            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Registration error: {e}")
            return render_template('registration.html')

    return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                logging.info(f"User logged in: {username}")
                return redirect(url_for('dashboard', username=username))
            else:
                return render_template('login.html')

        except Exception as e:
            logging.error(f"Login error: {e}")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/dashboard/<username>')
def dashboard(username):
    return f"<h2>Welcome to your dashboard, {username}!</h2>"


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
