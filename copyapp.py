from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import gettempdir

from helpers import *

# configure application
app = Flask(__name__)

# ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# custom filter
app.jinja_env.filters["usd"] = usd

# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = gettempdir()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

@app.route("/")
@login_required
def index():
    # get symbols of stocks bought by user.
    stock_symbols = db.execute("SELECT symbol FROM transaction WHERE u_id=:u_id GROUP BY symbol;", u_id=session['user_id'])
    grand_total = 0

    if stock_symbols != []:
        stocks = []
        current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id;", user_id=session['user_id'])

        for symbol in stock_symbols:
            symbol_data = lookup(symbol['symbol'])
            stock_shares = db.execute("SELECT SUM(quantity) FROM transaction WHERE u_id=:u_id AND symbol = :symbol;", \
            u_id=session['user_id'], symbol=symbol_data['symbol'])
            if stock_shares[0]['SUM(quantity)'] == 0:
                continue
            else:
                stock_info = {}

                stock_info['name'] = symbol_data['name']
                stock_info['symbol'] = symbol_data['symbol']
                stock_info['price'] = symbol_data['price']
                stock_info['shares'] = stock_shares[0]['SUM(quantity)']
                stock_info['total'] = stock_info['shares'] * stock_info['price']

                stocks.append(stock_info)

        for i in range(len(stocks)):
            grand_total += stocks[i]['total']
        grand_total += current_cash[0]['cash']

        for i in range(len(stocks)):
            stocks[i]['price'] = usd(stocks[i]['price'])
            stocks[i]['total'] = usd(stocks[i]['total'])

        return render_template("index.html", stocks=stocks, current_cash=usd(current_cash[0]['cash']), grand_total=usd(grand_total))

    else:
        current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session['user_id'])
        return render_template("index.html", current_cash=usd(current_cash[0]['cash']), grand_total = usd(current_cash[0]['cash']))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock."""
    if request.method == "POST":
        # check if valid input
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("enter some input")

        # if symbol is empty return apology
        if not symbol:
            return apology("enter a valid symbol")

        # if shares is empty
        if not shares or shares <= 0:
            return apology("enter the quantity of shares")

        # if can't afford to buy then error
        # get cash from db
        cashOnHand = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session["user_id"])
        cashOnHand = int(cashOnHand[0]['cash'])
        if (shares * symbol['price']) > cashOnHand:
            return apology("can't afford")
        else:
            db.execute("INSERT INTO transaction (symbol, shares, price, user_id) VALUES (:symbol, :shares, :price, :user_id)", \
            symbol=symbol['symbol'], shares=shares, price=symbol['price'], user_id=session["user_id"])
            # update cash (define old_balance)
            db.execute("UPDATE users SET cash=cash-:total_price WHERE id=:user_id;", total_price=shares*symbol['price'], \
            user_id=session["user_id"])
            return redirect(url_for("index"))

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions."""
    stocks = db.execute("SELECT symbol, quantity, price, date_time FROM transactions WHERE u_id=:u_id", u_id=session['user_id'])

    for stock in stocks:
        stock['price'] = usd(stock['price'])

    return render_template("history.html", stocks=stocks)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # ensure username exists and password is correct
        if len(rows) != 1 or not pwd_context.verify(request.form.get("password"), rows[0]["hash"]):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("login"))

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("stock not found")
        else:
            quote['price'] = usd(quote['price'])
            return render_template("quote.html", quote=quote)
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""
    # manipulate the information the user has submitted
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password")

        # ensure password confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password confirmation")

        # ensure password and confirmation match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match")

        # store the hash of the password and not the actual password that was typed in
        password = request.form.get("password")
        hash = pwd_context.encrypt(password)

        # username must be a unique field
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", \
        username=request.form.get("username"), hash=hash)
        if not result:
            return apology("pick a different username")

        # store their id in session to log them in automatically
        user_id = db.execute("SELECT id FROM users WHERE username IS :username",\
        username=request.form.get("username"))
        session['user_id'] = user_id[0]['id']
        return redirect(url_for("index"))

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell a stock"""
    if request.method == "POST":
        # check if valid input
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("enter some input")

        # if symbol is empty return apology
        if not symbol:
            return apology("enter a valid symbol")

        # if shares is empty
        if not shares or shares <= 0:
            return apology("enter the quantity of shares")

        # is the stock in the portfolio?
        stocks_held = db.execute("SELECT SUM(quantity) FROM transactions WHERE u_id=:u_id AND symbol=:symbol;", \
        u_id=session['user_id'], symbol=symbol['symbol'])
        if not stocks_held[0]['SUM(quantity)'] :
            return apology("you don't own this stock")

        # is shares less or = to the stocks held?
        if shares > stocks_held[0]['SUM(quantity)']:
            return apology("you don't own that many stocks")

        # enter a new transaction in transactions
            # ensure a sale is a negative number
        db.execute("INSERT INTO transactions (symbol, quantity, price, u_id) VALUES (:symbol, :quantity, :price, :u_id);", \
        symbol=symbol['symbol'], quantity=-shares, price=symbol['price'], u_id=session["user_id"])

        # update cash
        db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id;", total_price=shares*symbol['price'], \
        user_id=session["user_id"])

        return redirect(url_for('index'))

    else:
        return render_template("sell.html")

@app.route("/account", methods=["GET", "POST"])
def account():
    """Change user password"""
    # manipulate the information the user has submitted
    if request.method == 'POST':

        # ensure old password was submitted
        if not request.form.get('password'):
            return apology("must provide old password")

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session['user_id'])

        # ensure username exists and password is correct
        if len(rows) != 1 or not pwd_context.verify(request.form.get('password'), rows[0]['hash']):
            return apology("old password invalid")

        # ensure new password was submitted
        if not request.form.get("new-password"):
            return apology("must provide new password")

        # ensure password confirmation was submitted
        if not request.form.get("password-confirm"):
            return apology("must provide password confirmation")

        # ensure password and confirmation match
        if request.form.get("new-password") != request.form.get("password-confirm"):
            return apology("passwords must match")

        # store the hash of the password and not the actual password that was typed in
        password = request.form.get("new-password")
        hash = pwd_context.encrypt(password)

        # username must be a unique field
        result = db.execute("UPDATE users SET hash=:hash", hash=hash)
        if not result:
            return apology("that didn't work")

        return redirect(url_for("index"))

    else:
        return render_template("account.html")