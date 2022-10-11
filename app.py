# export API_KEY=pk_27b86d6ee64e49a493ac8ca81227a31d
import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
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
    #set the session of user id to a variable
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    print(username)

    #SELECT symbol, price and sum of shares where user id = current session set to a variable called stocks
    stocks = db.execute("SELECT symbol,price, SUM(shares) as totalShares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    # SELECT cash from users where user id is in session, go into 1st value in dictionary and get rid of brackets "cash"
    cash = round(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"],1)

    #set total = cash for now
    total = cash 
    for stock in stocks:
        
        total += lookup(stock["symbol"])["price"] * stock["totalShares"]
        round(total,1)

    return render_template("index.html", cash=cash,stocks=stocks,total=total,user_id=user_id,username=username)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # get value from input field with name "symbol" and run debug
        symbol = request.form.get("symbol")
        checksymbol = lookup(symbol)
        if not checksymbol:
            return apology("must provide valid stock symbol")
        if symbol == None:
            return apology("Stock symbol not valid, please try again")

        shares = request.form.get("shares").upper()
        if not shares.isdigit():
             return apology("You cannot purchase partial shares.")

        #look up symbol price
        price = lookup(symbol)["price"]

        checksymbol = lookup(symbol)
        if not checksymbol:
            return apology("must provide valid stock symbol")


        #Select cash value from current user

        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"]
        user_id = session["user_id"]


        #define certain variables that will go into database
        transaction_value = -(price * float(shares))
        portfolio = cash + transaction_value
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        #make transaction value negative if it is a buy make it a positive if it is a sell
        if transaction_value < 0:
            action = "buy"
        elif transaction_value > 0:
            action = "sell"

        #check if user has enough funds
        if (price * float(shares)) > cash:
            return apology("Not enough funds")

        #update cash in each user
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash = cash - (price * float(shares)), user_id = session["user_id"])

        #update portfolio of each user
        db.execute("UPDATE users SET portfolio = :portfolio WHERE id = :user_id", portfolio = portfolio, user_id = session["user_id"])

        #add transaction information
        db.execute("INSERT INTO transactions (user_id,symbol,shares,price,transaction_value, date,action) VALUES(?,?,?,?,?,?,?)", user_id, symbol, shares, price,transaction_value,date,action)
        flash("Buy successful. You have bought " + symbol)
        return redirect ("/")
    else:
        return render_template("buy.html")




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])
    return render_template("history.html",transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

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
        # get symbol from user
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must stock symbol")

        #get current stock price of symbol inputted from user
        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("must provide valid stock symbol")
        print(usd(stock["price"]))

        if not lookup(symbol):
            return apology("invalid stock symbol")
        #return page parsing in through variables to give user info
        return render_template("quoted.html",name=stock["name"], symbol=stock["symbol"], price=stock["price"])
    else:
        return render_template("quote.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # get data from user-submitted form
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username")
        elif not password or not confirmation:
            return apology("must provide password")
        elif password != confirmation:
            return apology("password does not match")
        if password != confirmation:
            return apology("Passwords do not match")

        #use generate_password_hash function to create hash of password    

        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users(username, hash) VALUES (?,?)", username, hash)
            return redirect("/")
        except:
            return apology("Username has already been registered!")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        transactions = db.execute("SELECT symbol, shares, price FROM transactions WHERE user_id=:id", id=session["user_id"])
        symbol = request.form.get("symbol")
        price = lookup(symbol)["price"]
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"]
        user_id = session["user_id"]
        shares = int(float(request.form.get("shares")))
        print(shares)
        newshares = -abs(shares)
        transaction_value = (price * float(shares))
        portfolio = cash + transaction_value
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # If transaction is negative, it is a buy. Vice versa.

        if transaction_value < 0:
            action = "buy"
        elif transaction_value > 0:
            action = "sell"

        qty_shares_user = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]
        print(qty_shares_user)
        if int(qty_shares_user) < shares:
            return apology("Insufficient shares in account")
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash = cash + transaction_value, user_id = session["user_id"])
        db.execute("INSERT INTO transactions (user_id,symbol,shares,price,transaction_value, date,action) VALUES(?,?,?,?,?,?,?)", user_id, symbol, newshares, price,transaction_value,date,action)
        flash("Sell successful!")
        return redirect ("/")

    else:
        transactions = db.execute("SELECT DISTINCT symbol, shares, price FROM transactions WHERE user_id=:id", id=session["user_id"])
        return render_template("sell.html",transactions=transactions)


