import os

# from flask import Flask, flash, jsonify, redirect, render_template, request, session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
# from helpers import apology, login_required, lookup, usd

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import mkdtemp

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
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

@app.route("/")
@login_required
def index():

    #select  users info and portfolio; check to see if owns any stock
    user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = session["user_id"])
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = :user_id", user_id = session["user_id"])
    if portfolio == None:
        return apology("You don't own any stocks")

    #Variable to hold networth
    net_stock_assets = 0.0
    current_cash = user[0]["cash"]

    #iterate through each line in the portfolio table: calculate value of each holding; also add up net worth; then update portfolio
    for symbols in portfolio:
        symbol = symbols["symbol"]
        shares = symbols["shares"]
        current_price = lookup(symbol)
        current_price = current_price["price"]
        value = shares * current_price
        net_stock_assets += value
        db.execute("UPDATE portfolio SET current_price=:current_price, value=:value WHERE user_id=:user_id AND symbol=:symbol", \
        user_id=session["user_id"], symbol=symbol, current_price=current_price, value=value)

    #Add user's cash balance to the valuation of their holdings
    total_assets = 0.0
    total_assets = current_cash + net_stock_assets

    #Reselect the transactions table for user with updated values
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id=:user_id", user_id=session["user_id"])

    return render_template("index.html", name=user[0]["username"], cash=usd(user[0]["cash"]), \
    net=usd(total_assets), portfolio=portfolio)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        #check for valid input
        if not request.form.get("symbol"):
            return apology("Please input a valid Symbol and number of Shares")
        if not request.form.get("shares"):
            return apology("Please input a valid Symbol and number of Shares")
        shares = int(request.form.get("shares"))
        if (shares < 1):
            return apology("Please input a valid number of shares")

        #create variables for the symbol, the price, the shares
        symbol = request.form.get("symbol").upper()
        results = lookup(symbol)
        #check if valid input was given
        if results == None:
            return apology("Please enter a valid stock symbol")

        price = results["price"]
        shares = int(request.form.get("shares"))
        total_cost = shares * price


        #User's current cash amount
        cash = db.execute("SELECT cash FROM users WHERE id=:id_current", id_current=session["user_id"])
        cash_available = cash[0]['cash']

        #Can user afford new purchase
        if cash_available >= total_cost:

            #update user's portfolio
            portfolio = db.execute("SELECT * FROM portfolio WHERE user_id=:id AND symbol=:symbol", \
            id=session["user_id"], symbol=symbol)
            #If the user doesn't own any of that stock, add new entry to their portfolio
            if len(portfolio) == 0:
                db.execute("INSERT INTO portfolio (user_id, symbol, shares, current_price, value) VALUES (:user_id, :symbol, \
                :shares, :current_price, :value)", user_id=session["user_id"], symbol=symbol, shares=shares, current_price=price, \
                value=total_cost)
            else:
                ## calculate the new total of shares which is old shares from portfolio plus new (if it is a sell, then it will
                ## be a negative amount)
                new_shares_total = portfolio[0]["shares"] + shares
                db.execute("UPDATE portfolio SET shares=:shares WHERE user_id=:id AND symbol=:symbol", shares=new_shares_total, \
                id=session["user_id"], symbol=symbol)

            #Available cash after purchase
            new_cash = cash_available - total_cost

            #update user's available cash
            db.execute("UPDATE users SET cash=:new_cash WHERE id=:id_current", new_cash=new_cash, id_current=session["user_id"])

            #add entry into transactions database
            db.execute("INSERT INTO transactions (user_id, symbol, shares, purchase_price) VALUES (:user_id, :symbol, :shares, \
            :purchase_price)", user_id=session["user_id"], symbol=symbol, shares=shares, purchase_price=price)

            #where to go after transaction
            flash("Congratulations on the new stock!")
            return redirect(url_for("index"))

        #Apology if they can't afford
        else:
            return apology("You can't afford dat stock bae!")

    # Take user to BUY page
    else:
        return render_template("buy.html")




@app.route("/history")
@login_required
def history():
    #select  users info and transactions
    user = db.execute("SELECT * FROM users WHERE id=:user_id", user_id=session["user_id"])
    transactions = db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id=:user_id", user_id=session["user_id"])
    if transactions == None:
        return apology("You don't have any history")

    #Variable to hold networth
    net_stock_assets = 0.0
    current_cash = user[0]["cash"]

    #iterate through each line in the portfolio table: calculate value of each holding; also add up net worth; then update portfolio
    for symbols in portfolio:
        symbol = symbols["symbol"]
        shares = symbols["shares"]
        current_price = lookup(symbol)
        current_price = current_price["price"]
        value = shares * current_price
        net_stock_assets += value
        db.execute("UPDATE portfolio SET current_price=:current_price, value=:value WHERE user_id=:user_id AND symbol=:symbol", \
        user_id=session["user_id"], symbol=symbol, current_price=current_price, value=value)

    #Add user's cash balance to the valuation of their holdings
    total_assets = 0.0
    total_assets = current_cash + net_stock_assets

    #Reselect the transactions table for user with updated values
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id=:user_id", user_id=session["user_id"])

    return render_template("history.html", name=user[0]["username"], cash=usd(user[0]["cash"]), \
    net=usd(total_assets), transactions=transactions)




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
        results = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # ensure username exists and password is correct
        if len(results) != 1 or not pwd_context.verify(request.form.get("password"), results[0]["hash"]):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = results[0]["id"]

        # redirect user to home page
        flash("Logged In")
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
    flash("Successfully Logged Out")
    return redirect(url_for("login"))



@app.route("/currentprice")
@login_required
def currentprice():
    """Display the results of the quote request"""
    return render_template("currentprice.html", name=results["name"], price=results["price"], symbol=results["symbol"])



@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        #perform lookup
        symbol = request.form.get("symbol").upper()
        results = lookup(symbol)
        #check if valid name was given
        if results == None:
            return apology("Please enter a valid stock symbol")
        else:
            return render_template("currentprice.html", name=results["name"], price=usd(results["price"]), symbol=results["symbol"])

    #If user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user"""

    # forget any user_id
    session.clear()

    #If user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure valid input submitted
        if not request.form.get("username"):
            return apology("must provide username")
        elif not request.form.get("password"):
            return apology("must provide password")
        elif not request.form.get("confirmation"):
            return apology("Please confirm your password")
        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("Oop!  Looks like your passwords don't match")

        #use pwd_context.encrypt to hash their password
        hash_pass = pwd_context.hash(request.form.get("password"))

        # check if username exists already
        result = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if result:
            return apology("Oh No!  It looks like that username is already taken.  Please try again.")

        #add user to database
        db.execute("INSERT into users(username, hash) VALUES(:username, :hash)", \
        username=request.form.get("username"), hash=hash_pass)

        results = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        # remember which user has logged in
        session["user_id"] = results[0]["id"]

        # redirect user to home page
        flash("Registered")
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        #check for valid input
        if not request.form.get("symbol"):
            return apology("Please input a valid Symbol and number of Shares")
        if not request.form.get("shares"):
                    return apology("Please input a valid Symbol and number of Shares")

        #create variables for the symbol, the price, the shares
        symbol = request.form.get("symbol").upper()
        results = lookup(symbol)
        shares = int(request.form.get("shares"))

        #check if valid input was given
        if results == None:
            return apology("Please enter a valid stock symbol")
        if (shares < 1) or (shares == None):
            return apology("Please enter a valid number of shares")

        price = results["price"]
        total_cost = shares * price

        #User's current portfolio of stocks
        portfolio= db.execute("SELECT shares FROM portfolio WHERE user_id=:id AND symbol=:symbol", \
        id=session["user_id"], symbol=symbol)

        #Current number of stocks in this company
        current_num_shares=portfolio[0]["shares"]

        #subtract number of shares wanting to sell from current number of shares
        new_num_shares=current_num_shares - shares

        #Get User's current cash amount
        cash=db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])

        #new cash amount
        new_cash = cash[0]["cash"] + total_cost

        #Does user have enough shares to sell and if any are left after sale
        if (current_num_shares - shares) > 0:
            #update user's portfolio
            db.execute("UPDATE portfolio SET shares=:shares WHERE user_id=:user_id AND symbol=:symbol", shares=new_num_shares, user_id=session["user_id"], symbol=symbol)

        #if after sell they have no more stock in that company
        elif (current_num_shares - shares) == 0:
            #update user's portfolio
            db.execute("DELETE FROM portfolio WHERE user_id=:id AND symbol=:symbol", \
            id=session["user_id"], symbol=symbol)

        #Apology if they can't afford
        else:
            return apology("You don't own dat many!")

        #update users new cash amount
        db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=new_cash, id=session["user_id"])

        #add entry into transactions database
        db.execute("INSERT INTO transactions (user_id, symbol, shares, purchase_price) VALUES (:user_id, :symbol, :shares, \
        :purchase_price)", user_id=session["user_id"], symbol=symbol, shares=(-1)*shares, purchase_price=price)

        #where to go after transaction
        flash("Sold Succefully")
        return redirect(url_for("index"))

    # Take user to Sell landing page
    else:
        return render_template("sell.html")

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        #check for valid input
        if not request.form.get("old1"):
            return apology("Please input your current password")
        if not request.form.get("old2"):
            return apology("Please confirm your current password")
        if not request.form.get("new"):
            return apology("Please enter a new password")
        old1 = request.form.get("old1")
        old2 = request.form.get("old2")
        new = request.form.get("new")
        if not (old1 == old2):
            return apology("Oops, it looks like your input for your current password did match")

        #use pwd_context.encrypt to hash their password
        hash_pass = pwd_context.hash(new)

        #add user to database
        db.execute("UPDATE users SET hash=:hash WHERE id=:id", id=session["user_id"], hash=hash_pass)

        flash("Your password has been updated")
        return render_template("index.html")
    #If user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html")