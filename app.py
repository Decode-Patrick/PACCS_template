import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required


# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.add_url_rule('/static/styles.css', 'styles.css', build_only=True)

Session(app)

#Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")

db.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL
)
""")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/publications")
def publications():
    return render_template("publications.html")


@app.route("/events")
def events():
    return render_template("events.html")

@app.route("/gis")
def gis():
    return render_template("gis.html")

@app.route("/capacity_building")
def capacity_building():
    return render_template("capacity_building.html")

ALLOWED_USERS = ["Louise", "Fadal", "Hakim", "Patrick"]

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return render_template ("apology.html", apology="Need username!")

        elif not password:
            return render_template("apology.html", apology="Need Password!")

        elif not confirmation:
            return render_template("apology.html", apology="Confirmation!")

        elif password != confirmation:
            return render_template("apology.html", apology="Password and Confirmation Do Not Match!")

        # Check if the user is on the list allowed to register
        if username not in ALLOWED_USERS:
            return render_template("apology.html", apology="Contact Louise for permission to access!")
        hash = generate_password_hash(password)

        try:
            new_user = db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)", username, hash
            )

            session["user_id"] = new_user
            flash("Registration successful. You can now log in.")
            return redirect("/login")

        except ValueError as e:
            if "UNIQUE constraint failed: users.username" in str(e):
                return render_template("apology.html", apology="Sorry, this Username is Taken.")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login User"""

    if request.method == "GET":
        return render_template("login.html")

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return render_template("apology.html", apology="Need Username!")

        elif not password:
            return render_template("apology.html", apology="Need Password!")


        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("apology.html", apology="Invalid username and/or password!")


        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return render_template("input.html")

@app.route("/logout")
def logout():
    session.clear()

    return redirect("/")
