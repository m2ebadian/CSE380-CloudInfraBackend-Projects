import sqlite3
import os
from flask import Flask, request
import hashlib
import json
import hmac
import base64
import requests

app = Flask(__name__)
db_name = "user.db"
sql_file = "user.sql"
db_flag = False

def create_db():
    conn = sqlite3.connect(db_name)
    with open(sql_file, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True

def get_db():
    if not db_flag:
        create_db()
    return sqlite3.connect(db_name)

@app.route('/clear', methods=['GET'])
def clear():
    try:
        if os.path.exists(db_name):
            os.remove(db_name)
        create_db()
        return {}, 200
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/create_user', methods=['POST'])
def create_user():
    conn = None
    try:
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email_address')
        password = request.form.get('password')
        salt = request.form.get('salt')
        employee = request.form.get('employee', 'False')

        if not all([first_name, last_name, username, email, password, salt]):
            return json.dumps({"status": 4, "pass_hash": "NULL"}), 200

        is_employee = 1 if str(employee).lower() == 'true' else 0

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return json.dumps({"status": 2, "pass_hash": "NULL"}), 200

        cursor.execute("SELECT 1 FROM users WHERE email_address = ?", (email,))
        if cursor.fetchone():
            return json.dumps({"status": 3, "pass_hash": "NULL"}), 200

        if not is_valid_password(password, first_name, last_name, username):
            return json.dumps({"status": 4, "pass_hash": "NULL"}), 200

        password_hash = hash_password(password, salt)

        cursor.execute("""INSERT INTO users (first_name, last_name, username, email_address, employee, password_hash, salt)
                          VALUES (?, ?, ?, ?, ?, ?, ?)""",
                       (first_name, last_name, username, email, is_employee, password_hash, salt))

        user_id = cursor.lastrowid
        cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)", (user_id, password_hash))
        conn.commit()

        try:
            requests.post(
                "http://logs:5000/log",
                data={"event": "user_creation", "user": username, "name": "NULL"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        except:
            pass  

        return json.dumps({"status": 1, "pass_hash": password_hash}), 200

    except Exception:
        return json.dumps({"status": 4, "pass_hash": "NULL"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    conn = None
    try:
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return json.dumps({"status": 2, "jwt": "NULL"}), 200

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return json.dumps({"status": 2, "jwt": "NULL"}), 200

        stored_hash, salt = row
        if hash_password(password, salt) != stored_hash:
            return json.dumps({"status": 2, "jwt": "NULL"}), 200

        token = generate_jwt(username)
        try:
            requests.post(
                "http://logs:5000/log",
                data={"event": "login", "user": username, "name": "NULL"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        except:
            pass

        return json.dumps({"status": 1, "jwt": token}), 200

    except Exception:
        return json.dumps({"status": 2, "jwt": "NULL"}), 500
    finally:
        if conn:
            conn.close()

def is_valid_password(password, first, last, user):
    if len(password) < 8: return False
    if not any(c.islower() for c in password): return False
    if not any(c.isupper() for c in password): return False
    if not any(c.isdigit() for c in password): return False
    lower = password.lower()
    return not (first.lower() in lower or last.lower() in lower or user.lower() in lower)

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def get_secret_key():
    try:
        with open("key.txt", "r") as f:
            return f.read().strip()
    except:
        return None
    
def base64url_encode(data):
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded

def generate_jwt(username):
    conn = None
    try:
        key = get_secret_key()
        if not key:
            return "NULL"

        header_json = json.dumps({"alg": "HS256", "typ": "JWT"}).encode('utf-8')
        header_b64 = base64url_encode(header_json)

        payload = {"username": username}
        payload_json = json.dumps(payload).encode('utf-8')
        payload_b64 = base64url_encode(payload_json)

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = hmac.new(key.encode('utf-8'), message, hashlib.sha256).hexdigest()

        jwt_token = f"{header_b64}.{payload_b64}.{signature}"
        return jwt_token

    except Exception:
        return "NULL"




@app.route('/check_employee', methods=['POST'])
def check_employee():
    conn = None
    try:
        username = request.form.get('username')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT employee FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return json.dumps({"employee": row[0]}), 200
        else:
            return json.dumps({"employee": 0}), 200
    except Exception as e:
        return json.dumps({"employee": 0}), 500
    finally:
        if conn:
            conn.close()