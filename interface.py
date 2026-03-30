import sys
import dataBaseAPI as db
import server as sr
import time
import uuid

# Main menu shown at startup
# lets the user register, log in and exit
def startScreen():
    print("Welcome")
    while True:
        function = input("choose function:\n1) Register\n2) Log in\n0) exit\n")
        match function:
            case "1":
                register()
            case "2":
                login()
            case "0":
                return False
            case _:
                print("Try again")

# Handles the login flow including 2FA verification
def login():
    username = input("Username:")
    password = input("password:")
    # Generate a unique nonce and timestamp to prevent replay attacks
    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    status = db.logIn(username, password, nonce, timestamp)

    if status == False:
        print("Wrong password or username")
        return

    if status == "replay":
        print("Replay attack detected")
        return

    if status == "locked":
        print("Account locked. Try again later.")
        return

    if status == "2fa_required":
        sr.TwoFactorGen(username)
        code = input("Give 2FA code: ")

        if not sr.TwoFactorCheck(username, code):
            print("Authentication failed")
            return

        print("Authentication successful")
        mainMenu(username)
    return None

# Registers a new user with a validated password
def register():
    username = input("Give user name: ")
    password = checkPass()
    db.newUser(username, password)
    startScreen()
    return None

# Prompts the user to create a password that fills the requirements
# min 12 characters and at least one special character
def checkPass():
    special_chars = set("!@#€%&$")
    while True:
        password = input("Create password\nMust contain 12 characters and a special symbol (!@#€%&$)\nPassword: ")
        if len(password) >= 12 and any(c in special_chars for c in password):
            return password
        print("Password does not meet requirements!")

# Shown users "dashboard" after successful login
def mainMenu(username):
    print("You have reached secret files")
    while True:
        func = input("1) print hashed password\n2) Logout\n0) exit\nchoose function: ")
        if func == "1":
            print(db.printHash(username))
        elif func == "2":
            startScreen()
        elif func == "0":
            sys.exit()
        else:
            print("Wrong function")

startScreen()
