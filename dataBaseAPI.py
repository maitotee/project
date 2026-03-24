import sqlite3
import bcrypt


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

def logIn(username, password):
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