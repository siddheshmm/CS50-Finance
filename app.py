import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session['user_id']
    transactionsdb = db.execute('select symbol, sum(shares) as shares, price from transactions where user_id = ? group by symbol', user_id)
    cashdb = db.execute('select cash from users where id=?', user_id)
    cash = cashdb[0]['cash']

    return render_template('index.html', database=transactionsdb, cash=cash)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'GET':
        return render_template('buy.html')
    else:
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        if not shares.isdigit():
            return apology("You cannot purchase partial shares.")

        shares = int(shares)

        if not symbol:
            return apology('must give a symbol', 400)

        stock = lookup(symbol)

        if stock == None:
            return apology('symbol does not exist', 400)

        if shares < 0:
            return apology('share not allowed', 400)

        transactionval = shares * stock['price']

        user_id = session['user_id']

        usercashdb = db.execute('select cash from users where id = ?', user_id)
        usercash = usercashdb[0]['cash']

        if usercash < transactionval:
            return apology('not enough cash', 400)

        updatecash = usercash - transactionval

        db.execute('update users set cash = ? where id = ?', updatecash, user_id)

        date = datetime.datetime.now()
        newuser = db.execute('INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)', user_id, stock['symbol'], shares, stock['price'], date)

        flash("Bought!")
        return redirect('/')

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session['user_id']
    transactionsdb = db.execute('select * from transactions where user_id=?', user_id)
    return render_template('history.html', transactions = transactionsdb)

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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

    if request.method == 'GET':
        return render_template('quote.html')
    else:
        symbol = request.form.get('symbol')

        if not symbol:
            return apology('must give a symbol', 400)

        stock = lookup(symbol)

        if stock == None or not stock:
            return apology('symbol does not exist', 400)

        return render_template('quoted.html', price = stock['price'], symbol = stock['symbol'])

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if request.method == "GET":
        # Ensure username was submitted
        return render_template('register.html')
    else:
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not password:
            return apology("must provide password", 400)

        if not confirmation:
            return apology("must confirm password", 400)

        #Ensure that password was re-entered
        if password != confirmation:
            return apology("passwords must be same", 400)

        #personal touch: username and password cannot be the same
        if username == password:
            return apology("password cannot be your username", 400)

        hash = generate_password_hash(password)

        try:
            newuser = db.execute('INSERT INTO users (username, hash) VALUES (?, ?)', username, hash)
        except ValueError:
            return apology('username already exists', 400)

        # Remember which user has logged in
        session["user_id"] = newuser
        return redirect('/')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'GET':
        user_id = session['user_id']
        symbols_user = db.execute('select symbol from transactions where user_id = ? group by symbol having sum(shares) > 0', user_id)
        return render_template('sell.html', symbols = [row['symbol'] for row in symbols_user])
    else:
        symbol = request.form.get('symbol')
        shares = int(request.form.get('shares'))

        if not symbol:
            return apology('must give a symbol', 400)

        stock = lookup(symbol)

        try:
            share = int(request.form.get("shares"))
        except ValueError:
                return apology("must provide a number", 400)

        if stock == None:
            return apology('symbol does not exist', 400)
        if shares < 0:
            return apology('share not allowed', 400)

        transactionval = stock['price'] * shares
        user_id = session['user_id']
        usercashdb = db.execute('select cash from users where id = ?', user_id)
        usercash = usercashdb[0]['cash']

        user_shares = db.execute('select shares from transactions where user_id = ? and symbol = ? group by symbol', user_id, symbol)
        usersharesreal = user_shares[0]['shares']

        if shares > usersharesreal:
            return apology('not enough shares..', 400)

        updatecash = usercash + transactionval

        db.execute('update users set cash = ? where id = ?', updatecash, user_id)

        date = datetime.datetime.now()
        newuser = db.execute('INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)', user_id, stock['symbol'], (-1 * shares), stock['price'], date)

        flash("Sold!")
        return redirect('/')
