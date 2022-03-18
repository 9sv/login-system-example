import configparser
import hashlib
import secrets
import sqlite3
from http import HTTPStatus

from flask import (Flask, Response, abort, redirect, render_template,
                   render_template_string, request, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ext.reset_pass import reset_codes, send_reset_code

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

@app.before_first_request
def check_db():
    """
    Create a database connection and cursor if one doesn't exist
    """
    global database
    global cursor
    global config
    config = configparser.ConfigParser().read("config.ini")
    database = sqlite3.connect('logins.db', check_same_thread=False)
    cursor = database.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS `logins` (
            `username` varchar(25) NOT NULL UNIQUE,
            `email` TEXT NOT NULL UNIQUE,
            `password` TEXT NOT NULL
        );""")
    database.commit()

@app.route('/', methods=["GET"])
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
@limiter.limit('10/minute', methods=["POST"])
def login():
    if (request.method == "GET"):
        return render_template('login.html', register=url_for('register'))
    if (request.method == "POST"):
        if (not request.form.get('username', False) or not request.form.get('password', False)):
            return abort(400)
        cursor.execute("SELECT password FROM `logins` WHERE username=?;", (request.form.get('username'),))
        row = cursor.fetchone()
        if not row:
            return abort(Response("Invalid Password", HTTPStatus.UNAUTHORIZED))
        hash, salt = row[0].split(':')
        password_match = bool(str(hash) == str(hashlib.sha256(str(salt).encode() + str(request.form.get('password')).encode()).hexdigest()))
        if password_match:
            return redirect('https://google.com/')
        else:
            return abort(Response("Invalid Password", HTTPStatus.UNAUTHORIZED))

@app.route('/register', methods=["GET", "POST"])
@limiter.limit('1/15 minutes', methods=["POST"])
def register():
    if (request.method == "GET"):
        return render_template('register.html', login=url_for('login'))
    if (request.method == "POST"):
        if (not request.form.get('username', False) or not request.form.get('password', False) or not request.form.get('email', False)):
            return abort(400)
        cursor.execute("SELECT username FROM `logins` WHERE username=? OR email=?;", (request.form.get('username'), request.form.get('username')))
        if bool(cursor.fetchone() is not None):
            return abort(Response("That username already exists", HTTPStatus.UNAUTHORIZED))
        salt = secrets.token_hex(128)
        password = str(hashlib.sha256(salt.encode() + str(request.form.get('password')).encode()).hexdigest() + ':' + salt)
        cursor.execute("INSERT INTO `logins` (username, password, email) VALUES (?, ?, ?);", (request.form.get('username'), password, request.form.get('email')))
        database.commit()
        return redirect(url_for('login'))

@app.route('/reset_password', methods=["GET", "POST"])
@limiter.limit('1/30 minutes', methods=["POST"])
def reset_password():
    if (request.method == "GET"):
        return render_template('forgot.html', login=url_for('login'))
    if (request.method == "POST"):
        if (not request.form.get('username', False)):
            return abort(400)
        cursor.execute("SELECT email FROM `logins` WHERE username=? OR email=?", (request.form.get('username'), request.form.get('username')))
        row = cursor.fetchone()
        if bool(row is None):
            return abort(Response("No account found", HTTPStatus.UNAUTHORIZED))
        email = row[0]
        send_reset_code(email, config)
        return Response("Reset link sent to email", 200)

@app.route('/reset_password/<token>', methods=["GET", "POST"])
def handle_token(token):
    try:
        email = reset_codes[str(token)]
    except KeyError:
        return Response('Invalid Token')
    cursor.execute("SELECT username FROM `logins` WHERE email=?", (email,))
    username = cursor.fetchone()[0]
    if (request.method == "GET"):
        return render_template('reset.html')
    if (request.method == "POST"):
        if (not request.form.get('password', False)):
            return abort(400)
        salt = secrets.token_hex(128)
        password = str(hashlib.sha256(salt.encode() + str(request.form.get('password')).encode()).hexdigest() + ':' + salt)
        cursor.execute("UPDATE `logins` SET password=? WHERE username=?;", (password, username))
        database.commit()
        del reset_codes[token]
        return render_template_string('Password Reset Successfully\nYou can return to login <a href={{login}}>here</a>', login=url_for('login'))

if __name__ == "__main__":
    app.run()
