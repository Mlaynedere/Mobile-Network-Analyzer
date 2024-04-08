from flask import Flask, redirect, url_for, request, render_template
from flask_bcrypt import Bcrypt
from flask_session import Session
import os
import base64
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SESSION_TYPE'] = 'filesystem' ##Sessions are stored locallys
app.config['SECRET_KEY'] = os.urandom(128) ## Session key is 128 bits long to prevent brute-force attacks
app.config['SESSION_COOKIE_HTTPONLY'] = True #Browsers will not allow JavaScript access to cookies marked as “HTTP only” for security
app.config['SESSION_COOKIE_SECURE'] = True #Browsers will only send cookies with requests over HTTPS if the cookie is marked “secure”. The application must be served over HTTPS for this to make sense
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' #Restrict how cookies are sent with requests from external sites

Session(app)


def generate_salt():
    """Generate a cryptographically secure random salt."""
    salt = os.urandom(86) ## Generate a salt of 86 bits for security and at the same time not too long for conveniency
    return base64.b64encode(salt).decode('utf-8')


def validate_password(password):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long'

    if len(re.findall(r'\d', password)) < 2:
        return False, 'Password must contain at least 2 numbers'

    if not any(char.isupper() for char in password):
        return False, 'Password must contain at least one capital letter'

    if not any(char in '!@#$%^&*()-_=+[{]}|;:",<.>/?' for char in password):
        return False, 'Password must contain at least one special character'

    return True, None

user_credentials = {}

@app.route('/')
def hello():
    return 'Hello World'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate password

        is_valid, error_message = validate_password(password)
        if not is_valid:
            return render_template('register.html', error=error_message)
        
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
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            if username in user_credentials:
                stored_hashed_password = user_credentials[username]['hashed_password']
                salt = user_credentials[username]['salt']
                # Combine password with salt and hash it
                hashed_password = bcrypt.generate_password_hash(password + salt).decode('utf-8')
                if stored_hashed_password == hashed_password:
                    Session['username'] = username
                    return redirect(url_for('success', name=username))
                else:
                    # Render login page with error message
                    return render_template('login.html', error='Invalid username or password')
            else:
                return render_template('login.html', error='Invalid username or password')
        return render_template('login.html', error=None)

@app.route('/success/<name>')
def success(name):
    if 'username' in Session:
        username = Session['username']
        return 'Welcome, %s!' % name
    else:
         return redirect(url_for('login'))  # Redirect to login if user is not logged in
app.run(host="0.0.0.0", debug = True)
