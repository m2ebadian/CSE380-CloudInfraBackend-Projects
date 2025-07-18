import sqlite3
import json
import os
import base64
import hmac
import hashlib
import requests

from flask import Flask, request

app = Flask(__name__)
db_name = "logs.db"
sql_file = "logs.sql"

def create_db():
    conn = sqlite3.connect(db_name)
    with open(sql_file, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

def get_secret_key():
    try:
        with open("key.txt", "r") as f:
            return f.read().strip()
    except:
        return None

def verify_jwt(jwt_token):
    try:
        header_b64, payload_b64, signature = jwt_token.split(".")
        secret_key = get_secret_key()
        if not secret_key:
            return None

        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode())
        username = payload.get("username")

        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        computed_signature = hmac.new(secret_key.encode(), message, hashlib.sha256).hexdigest()

        if computed_signature != signature:
            return None

        return username
    except:
        return None

@app.route('/clear', methods=['GET'])
def clear_logs():
    try:
        if os.path.exists(db_name):
            os.remove(db_name)
        create_db()
        return {}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@app.route('/log', methods=['POST'])
def log_event():
    try:
        event = request.form.get("event")
        user = request.form.get("user")
        name = request.form.get("name", "NULL")

        if not all([event, user]):
            return {"status": 2}, 200

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (event, username, name) VALUES (?, ?, ?)", (event, user, name))
        conn.commit()
        conn.close()

        return {"status": 1}, 200
    except:
        return {"status": 2}, 200

@app.route('/view_log', methods=['GET'])
def view_log():
    try:
        jwt_token = request.headers.get('Authorization')
        username = verify_jwt(jwt_token)
        if not username:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        target_user = request.args.get("username")
        product = request.args.get("product")

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        logs = []
        if target_user:
            if target_user != username:
                return json.dumps({"status": 3, "data": "NULL"}), 200
            cursor.execute("SELECT event, username, name FROM logs WHERE username = ?", (target_user,))
        elif product:
            
            response = requests.get("http://user:5000/is_employee", headers={"Authorization": jwt_token})
            if response.status_code != 200 or response.json().get("status") != 1:
                return json.dumps({"status": 3, "data": "NULL"}), 200
            cursor.execute("SELECT event, username, name FROM logs WHERE name = ?", (product,))
        else:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        log_entries = cursor.fetchall()
        conn.close()

        data = {i+1: {"event": row[0], "user": row[1], "name": row[2]} for i, row in enumerate(log_entries)}
        return json.dumps({"status": 1, "data": data}), 200
    except:
        return json.dumps({"status": 2, "data": "NULL"}), 200




@app.route('/_internal_last_modifier', methods=['GET'])
def internal_last_modifier():
    try:
        product_name = request.args.get('product_name')
        if not product_name:
            return json.dumps({"last_mod": "unknown"}), 200

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        
        cursor.execute("""
            SELECT username FROM logs
            WHERE name = ? AND (event = 'product_creation' OR event = 'product_edit')
            ORDER BY timestamp DESC LIMIT 1
        """, (product_name,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return json.dumps({"last_mod": row[0]}), 200
        else:
            return json.dumps({"last_mod": "unknown"}), 200
    except Exception as e:
        return json.dumps({"last_mod": "unknown"}), 200
