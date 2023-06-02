from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///main.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# ==================INDEX=================#
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    username = db.execute(
        "SELECT username FROM users WHERE id = ?;", session["user_id"])
    username = username[0]['username']

    return render_template("index.html", username=username)


# =============================== LOGIN ====================================
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# ========================REGISTER=================== #
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password verifications was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password verification", 400)

        # Ensure passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match", 400)

        # Ensure username is not taken
        elif len(db.execute("SELECT username FROM users WHERE username = ?;", request.form.get("username"))) != 0:
            return apology("Sorry, user name is already taken", 400)

        # Adding the username and hash to the database
        else:
            hash = generate_password_hash(request.form.get(
                "password"), method='pbkdf2:sha256', salt_length=16)

            db.execute("INSERT INTO users (username, hash) VALUES(?, ?);", request.form.get("username"), hash)
            session["user_id"] = \
                db.execute("SELECT id FROM users WHERE username = ?;", request.form.get("username"))[0]['id']
            return redirect("/")

    return render_template("register.html")


# =========CHANGE PASS ========#


@app.route("/chpass", methods=["GET", "POST"])
@login_required
def chpass():
    """Change Password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        pass_hash = db.execute("SELECT hash FROM users WHERE id = ?;", session["user_id"])
        # Ensure Old password is correct
        if not check_password_hash(pass_hash[0]['hash'], request.form.get("old_password")):
            return apology("wrong password", 403)

        # No old pass blank
        elif not request.form.get("old_password"):
            return apology("must provide password", 400)

        # no blank password
        elif not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # No confirmation Blank
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation of password", 400)

        # password doesn't match confirmation
        elif request.form.get("new_password") != request.form.get("confirmation"):
            return apology("passwords don't match", 400)

        else:
            hash = generate_password_hash(request.form.get(
                "new_password"), method='pbkdf2:sha256', salt_length=16)

            db.execute("UPDATE users SET hash = ? WHERE id = ?;", hash, session["user_id"])
            flash("success")
            return redirect("/")

    return render_template("chpass.html")
