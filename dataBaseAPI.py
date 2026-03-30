import sqlite3
import bcrypt
import time

# Returns True if the username already exists in the database
def CheckIfUserExists(username):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return c.fetchone() is not None


# Creates a new user with a bcrypt-hashed password
def newUser(username, password):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, passwordHash) VALUES (?, ?)", (username, hashed))
        conn.commit()
    return "ok"


# Verifies credentials and returns login status:
# "locked" when account is temporarily locked due to too many failed attempts
# False when user not found or wrong password
# "replay" when nonce has been used before or timestamp is too old
# "2fa_required" when password correct, 2FA code needed next
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


# Stores a new 2FA code and its expiry time for the user in database
def TwoFactorNew(username, code, expiry):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET TwoFACode = ?, TwoFAExpiry = ? WHERE username = ?",(code, expiry, username))
        conn.commit()


# Checks that the provided 2FA code matches the saved code in database and has not expired
def TwoFactorcheck(username, code):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT TwoFACode, TwoFAExpiry FROM users WHERE username = ?", (username,))
        result = c.fetchone()

        if not result:
            return False

        stored_code, expiry = result

        # Reject expired codes
        if int(time.time()) > expiry:
            return False

        return code == stored_code


# Protects against replay attacks:
# rejects requests with timestamps older than 30 seconds
# rejects nonces that have been used before
# cleans up expired nonces from the database
def ReplayCheck(c, nonce, timestamp):
    current_time = int(time.time())

    if abs(current_time - int(timestamp)) > 30:
        return False

    c.execute("DELETE FROM nonces WHERE timestamp < ?", (current_time - 30,))

    c.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
    if c.fetchone():
        return False

    c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)",(nonce, timestamp))

    return True


# Returns False if the account is currently locked
# Automatically unlocks the account if the lock period has expired
def BruteforceCheck(c, username):
    c.execute("SELECT failedAttempts, lockUntil FROM users WHERE username = ?", (username,))
    result = c.fetchone()

    if not result:
        return True

    attempts, lockUntil = result
    current_time = int(time.time())

    if lockUntil and current_time >= lockUntil:
        # Lock is expired and reset the counter
        c.execute(
            "UPDATE users SET failedAttempts = 0, lockUntil = 0 WHERE username = ?",
            (username,)
        )
        return True

    if lockUntil and current_time < lockUntil:
        return False

    return True


# Increments failed login attempts
# locks the account for 60s after 5 failures
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


# Clears failed login attempts and any lock on successful login
def resetAttempts(c, username):
    c.execute("UPDATE users SET failedAttempts = 0, lockUntil = 0 WHERE username = ?",(username,))


# Returns the stored password hash for the given user
def printHash(username):
    with sqlite3.connect("UserDataBase.db", timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT passwordHash FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        return result
