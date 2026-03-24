import sys
import dataBaseAPI as db
import server as sr
import time
import uuid

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
        
def login():
    username = input("Username:")
    password = input("password:")
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

def register():
    username = input("Give user name: ")
    password =  checkPass()
    db.newUser(username, password)
    startScreen()
    return None
   
def checkPass():
    specialCaracters = ["!", "@", "#", "€", "%", "&", "$"]
    while True:
        password = input("Cretate password\nMust contain 12 caracters and special symbols\npassword:")
        for char in specialCaracters:
            if char in password and len(password)>=12:
                return password
        print("Password does not fill requirements!") 

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