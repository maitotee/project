import sqlite3
import bcrypt
import time

def CheckIfUserExists(username):
    conn = sqlite3.connect("UserDataBase.db")
    c = conn.cursor()
    
    c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result is not None

def newUser(username, password):
    conn = sqlite3.connect("UserDataBase.db")
    c = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (username, passwordHash) VALUES (?, ?)", (username, hashed))
    conn.commit()
    conn.close()
    return "ok"

def logIn(username, password, nonce, timestamp):
    msg = ReplayCheck(nonce, timestamp)
    if msg == False:
        return "Replay detected" 
    conn = sqlite3.connect("UserDataBase.db")
    c = conn.cursor()
    c.execute("SELECT passwordHash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return False
    
    stored_hash = result[0]
    return bcrypt.checkpw(password.encode(), stored_hash)

def TwoFactorNew(username, code, expiry):
    conn = sqlite3.connect("UserDataBase.db")
    c = conn.cursor()
    c.execute("UPDATE users SET TwoFACode = ?, TwoFAExpiry = ? WHERE username = ?", (code, expiry, username))
    conn.commit()
    conn.close()
    return None

def TwoFactorcheck(username):
    conn = sqlite3.connect("UserDataBase.db")
    c = conn.cursor()
    c.execute("SELECT TwoFACode, TwoFAExpiry FROM users WHERE username = ?",(username,))
    result = c.fetchone()
    conn.close()
    return result

def ReplayCheck(nonce, timestamp):
    conn = sqlite3.connect("UserDataBase.db")
    c = conn.cursor()
    
    current_time = int(time.time())

    if abs(current_time - int(timestamp)) > 30:
        conn.close()
        return False

    c.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
    if c.fetchone():
        conn.close()
        return False

    c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)",(nonce, timestamp))
    conn.commit()
    conn.close()

    return True