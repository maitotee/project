import random
import time
import dataBaseAPI as db

DB_NAME = "UserDataBase.db"

def TwoFactorGen(username):
    code = str(random.randint(100000, 999999))
    expiry = int(time.time()) + 60
    db.TwoFactorNew(username, code, expiry)
    print(f"[2FA CODE for {username}]: {code}")
    return code

def TwoFactorCheck(username, code):
    result = db.TwoFactorcheck(username)
    if not result:
        return False
    stored_code, expiry = result

    if int(time.time()) > expiry:
        return False

    if code == stored_code:
        return True
    return False