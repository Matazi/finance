import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user = session["user_id"]

    rows = db.execute("SELECT * FROM history WHERE user_id = :user_id",
                          user_id = session["user_id"])
    total = 0
    for row in rows:
        total = total + row["total"]
    print(total)

    return render_template("index.html", rows=rows, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provid symbol to quote", 403)

        #Ensure shares is a positive number
        if int(request.form.get("shares")) < 1:
            return apology("must buy at least 1 share", 403)

        symbol = lookup(request.form.get("symbol"))

        if symbol == None:
            return apology("Provided stock symbol does not exist", 403)

        #Check if user has enough money
        rows = db.execute("SELECT cash FROM users WHERE id = :idd",
                          idd = session["user_id"])

        shareprice = int(request.form.get("shares")) * symbol["price"]
        if len(rows) != 1:
            return apology("invalid username and/or password", 403)

        if rows[0]["cash"] <  shareprice:
            return apology("You don't have enough cash", 403)

        history =  db.execute("SELECT * FROM history WHERE user_id = :idd AND symbol = :symbol",
                          idd = session["user_id"], symbol= symbol["symbol"])
        # #Store informations in database
        if len(history) < 1:
            db.execute("INSERT INTO history (symbol, shares, price, user_id, name, total) VALUES (:symbol, :shares, :price, :user_id, :name, :total)",
            symbol = symbol["symbol"], shares = request.form.get("shares"), price = symbol["price"], user_id = session["user_id"], name = symbol["name"], total = shareprice)
        else:
            #Update existing row in history
            new_shares = history[0]["shares"] + int(request.form.get("shares"))
            db.execute("UPDATE history SET symbol=:symbol, shares=:shares, price=:price, user_id=:user_id, name=:name, total=:total WHERE symbol=:second",
            symbol = symbol["symbol"], shares = new_shares, price = symbol["price"], user_id = session["user_id"], name = symbol["name"], total = shareprice, second=symbol["symbol"])
            # Redirect user to home page
        return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provid symbol to quote")

        symbol = lookup(request.form.get("symbol"))

        if symbol == None:
            return apology("Provided stock symbol does not exist")

        # print(symbol)
        return render_template("quoted.html", symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username doesn't already exist
        if len(rows) != 0:
            return apology("Username already exists", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 403)

        # Ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation don't watch", 403)

        #Insert into database
        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username = username, hash = password)

        # Redirect user to login form
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        if not request.form.get("symbol"):
                return apology("must provid symbol to quote", 403)

        symbol = lookup(request.form.get("symbol"))


        #Make sure user owns stock inputted
        rows = db.execute("SELECT * FROM history WHERE symbol = :stock",
                          stock = request.form.get("symbol"))
        if len(rows) < 1:
            return apology("You don't own stocks in this company", 403)

        #Ensure shares is a positive number

        if not request.form.get("shares") or int(request.form.get("shares")) < 1:
            return apology("must sell at least 1 share", 403)

        #Ensure user owns enough stocks to sell

        if rows[0]["shares"] < int(request.form.get("shares")):
            return apology("You don't have enough shares to sell", 403)

        new_shares = rows[0]["shares"] - int(request.form.get("shares"))
        new_total = new_shares * symbol["price"]
        #Update shares of stock
        db.execute("UPDATE history SET shares=:shares, total=:total WHERE symbol=:second", shares = new_shares, total = new_total, second=symbol["symbol"])

        #Update users cash


        return redirect("/")
    else:

        rows = db.execute("SELECT * FROM history")

        symbols = []
        for row in rows:
            symbols.append(row["symbol"])

        return render_template("sell.html", symbols = symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
