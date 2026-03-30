import random
import time
import dataBaseAPI as db

# Generates a 6-digit 2FA code, stores it in the database with a 60-second expiry
# and prints it to the console simulating delivery via SMS
def TwoFactorGen(username):
    code = str(random.randint(100000, 999999))
    expiry = int(time.time()) + 60
    db.TwoFactorNew(username, code, expiry)
    print(f"[2FA CODE for {username}]: {code}")
    return code

# Verifies the 2FA code provided by the user
def TwoFactorCheck(username, code):
    return db.TwoFactorcheck(username, code)
