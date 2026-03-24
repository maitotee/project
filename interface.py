import sys
import dataBaseAPI as db
import server as sr

def startScreen():
    print("Welcome")
    while True:
        function = input("choose function:\n1) Register\n2) Log in\n0) exit\n")
        match function:
            case "1":
                register()
                return False
            case "2":
                login()
                return False
            case "0":
                return False
            case _:
                print("Try again")
        
def login():
    username = input("Username:")
    password = input("password:")
    status = db.logIn(username, password)
    if status == False:
        print("Wrong password or username")
    else:
        sr.TwoFactorGen(username)
        state = sr.TwoFactorCheck(username, input("Give 2FA code: "))
        if state == False:
            print("authentication failed\nreturning to start.")
            startScreen()
        else:
            
            print("Authentication succesful\nLogging in.....")
            mainMenu()
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

def mainMenu():
    print("olet sisässsä senkin femboy")
    sys.exit()
    return None
    
startScreen()