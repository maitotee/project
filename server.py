import random
import time
import dataBaseAPI as db

def TwoFactorGen(username):
    code = str(random.randint(100000, 999999))
    expiry = int(time.time()) + 60
    db.TwoFactorNew(username, code, expiry)
    print(f"[2FA CODE for {username}]: {code}")
    return code

def TwoFactorCheck(username, code):
    return db.TwoFactorcheck(username, code)