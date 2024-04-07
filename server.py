from flask import Flask, redirect, url_for, request, render_template
from flask_bcrypt import Bcrypt
import os
import base64

app = Flask(__name__)
bcrypt = Bcrypt(app)


def generate_salt():
    """Generate a cryptographically secure random salt."""
    salt = os.urandom(86) ## Generate a salt of 86 bits for security and conveniency
    return base64.b64encode(salt).decode('utf-8')


user_credentials = {}

@app.route('/')
def hello():
    return 'Hello World'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Generate a unique salt for each user
        salt = generate_salt()
        # Combine password with salt and hash it
        hashed_password = bcrypt.generate_password_hash(password + salt).decode('utf-8')
        # Store the username, hashed password, and salt in memory (temporary storage)
        user_credentials[username] = {'hashed_password': hashed_password, 'salt': salt}
        return 'User registered successfully'
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username in user_credentials:
        stored_hashed_password = user_credentials[username]['hashed_password']
        salt = user_credentials[username]['salt']
        # Combine password with salt and hash it
        hashed_password = bcrypt.generate_password_hash(password + salt).decode('utf-8')
        if stored_hashed_password == hashed_password:
            return redirect(url_for('success', name=username))
        else:
            # Render login page with error message
            return render_template('login.html', error='Invalid username or password')
    else:
        # Render login page
        return render_template('login.html', error=None)

@app.route('/success/<name>')
def success(name):
    return 'Welcome, %s!' % name
app.run(debug = True)