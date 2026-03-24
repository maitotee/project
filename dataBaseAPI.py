import sqlite3
import bcrypt
import time

def CheckIfUserExists(username):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return c.fetchone() is not None


def newUser(username, password):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, passwordHash) VALUES (?, ?)", (username, hashed))
        conn.commit()
    return "ok"


def logIn(username, password, nonce, timestamp):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()

        if not BruteforceCheck(c, username):
            return "locked"

        c.execute("SELECT passwordHash FROM users WHERE username = ?", (username,))
        result = c.fetchone()

        if not result:
            return False

        stored_hash = result[0]

        if not bcrypt.checkpw(password.encode(), stored_hash):
            updateAttemps(c, username)
            return False

        resetAttempts(c, username)
        
        if not ReplayCheck(c, nonce, timestamp):
            return "replay"

        return "2fa_required"


def TwoFactorNew(username, code, expiry):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET TwoFACode = ?, TwoFAExpiry = ? WHERE username = ?",(code, expiry, username))
        conn.commit()


def TwoFactorcheck(username, code):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT TwoFACode, TwoFAExpiry FROM users WHERE username = ?", (username,))
        result = c.fetchone()

        if not result:
            return False

        stored_code, expiry = result

        if int(time.time()) > expiry:
            return False

        return code == stored_code


def ReplayCheck(c, nonce, timestamp):
    current_time = int(time.time())

    if abs(current_time - int(timestamp)) > 30:
        return False

    c.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
    if c.fetchone():
        return False

    c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)",(nonce, timestamp))

    return True


def BruteforceCheck(c, username):
    c.execute("SELECT failedAttempts, lockUntil FROM users WHERE username = ?", (username,))
    result = c.fetchone()

    if not result:
        return True

    attempts, lockUntil = result
    current_time = int(time.time())

    if lockUntil and current_time >= lockUntil:
        c.execute(
            "UPDATE users SET failedAttempts = 0, lockUntil = 0 WHERE username = ?",
            (username,)
        )
        return True

    if lockUntil and current_time < lockUntil:
        return False

    return True


def updateAttemps(c, username):
    c.execute("SELECT failedAttempts FROM users WHERE username = ?", (username,))
    result = c.fetchone()

    if not result:
        return

    attempts = result[0] + 1
    current_time = int(time.time())

    if attempts >= 5:
        lock_until = current_time + 60
        attempts = 0
    else:
        lock_until = 0

    c.execute("UPDATE users SET failedAttempts = ?, lockUntil = ? WHERE username = ?",(attempts, lock_until, username))


def resetAttempts(c, username):
    c.execute("UPDATE users SET failedAttempts = 0, lockUntil = 0 WHERE username = ?",(username,))
    
    
def printHash(username):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT passwordHash FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        return result
    
    