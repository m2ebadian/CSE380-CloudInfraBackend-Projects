import sqlite3
import os
from flask import Flask, request
import json
import hmac
import base64
import hashlib
import requests

app = Flask(__name__)
db_name = "products.db"
sql_file = "products.sql"
db_initialized = False


def create_db():
    conn = sqlite3.connect(db_name)
    with open(sql_file, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    global db_initialized
    db_initialized = True


def get_db():
    if not db_initialized:
        create_db()
    return sqlite3.connect(db_name)


def get_secret_key():
    try:
        with open("key.txt", "r") as f:
            return f.read().strip()
    except Exception:
        return None


def verify_jwt_and_check_employee(jwt_token):
    parts = jwt_token.split('.')
    if len(parts) != 3:

        return False

    header_b64, payload_b64, signature = parts
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode('utf-8'))
        username = payload.get("username")

    except Exception as e:

        return False

    secret_key = get_secret_key()
    if not secret_key:

        return False

    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    computed_signature = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()

    if computed_signature != signature:
        return False

    try:
        response = requests.post(
            "http://user:5000/check_employee",
            data={"username": username},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        result = response.json()
        return result.get("employee") == 1
    except Exception as e:
        return False



@app.route('/create_product', methods=['POST'])
def create_product():
    jwt_token = request.headers.get('Authorization')
    if not jwt_token or not verify_jwt_and_check_employee(jwt_token):
        return json.dumps({"status": 2}), 200

    name = request.form.get("name")
    price = request.form.get("price")
    category = request.form.get("category")

    if not all([name, price, category]):
        return json.dumps({"status": 2}), 200

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (name, price, category) VALUES (?, ?, ?)", (name, float(price), category))
        conn.commit()
        conn.close()

       
        try:
            parts = jwt_token.split('.')
            payload_b64 = parts[1]
            padded_payload = payload_b64 + '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))
            username = payload.get("username")

            if username:
                requests.post(
                    "http://logs:5000/log",
                    data={"event": "product_creation", "user": username, "name": name},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
        except Exception:
            pass 

        return json.dumps({"status": 1}), 200
    except Exception:
        return json.dumps({"status": 2}), 200


@app.route('/edit_product', methods=['POST'])
def edit_product():
    jwt_token = request.headers.get('Authorization')
    if not jwt_token:
        return json.dumps({"status": 2}), 200
    if not verify_jwt_and_check_employee(jwt_token):
        return json.dumps({"status": 3}), 200

    name = request.form.get("name")
    new_price = request.form.get("new_price")
    new_category = request.form.get("new_category")

    if not name or (not new_price and not new_category):
        return json.dumps({"status": 2}), 200

    try:
        conn = get_db()
        cursor = conn.cursor()
        if new_price:
            cursor.execute("UPDATE products SET price = ? WHERE name = ?", (float(new_price), name))
        elif new_category:
            cursor.execute("UPDATE products SET category = ? WHERE name = ?", (new_category, name))
        conn.commit()
        conn.close()

        
        try:
            parts = jwt_token.split('.')
            payload_b64 = parts[1]
            padded_payload = payload_b64 + '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))
            username = payload.get("username")

            if username:
                requests.post(
                    "http://logs:5000/log",
                    data={"event": "product_edit", "user": username, "name": name},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
        except Exception:
            pass  

        return json.dumps({"status": 1}), 200
    except Exception:
        return json.dumps({"status": 2}), 200


@app.route('/clear', methods=['GET'])
def clear_database():
    try:
        if os.path.exists(db_name):
            os.remove(db_name)
        create_db()
        return {}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500







@app.route('/_internal_get_product_by_name', methods=['GET'])
def internal_get_product_by_name():
    name = request.args.get('name')
    if not name:
        return json.dumps([]), 200

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT name, price, category FROM products WHERE name = ?", (name,))
        row = cursor.fetchone()
        conn.close()

        if row:
            product = {"product_name": row[0], "price": row[1], "category": row[2]}
            return json.dumps([product]), 200
        else:
            return json.dumps([]), 200
    except:
        return json.dumps([]), 200


@app.route('/_internal_get_products_by_category', methods=['GET'])
def internal_get_products_by_category():
    category = request.args.get('category')
    if not category:
        return json.dumps([]), 200

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT name, price, category FROM products WHERE category = ?", (category,))
        rows = cursor.fetchall()
        conn.close()

        products = []
        for row in rows:
            products.append({"product_name": row[0], "price": row[1], "category": row[2]})

        return json.dumps(products), 200
    except:
        return json.dumps([]), 200





@app.route('/get_product_price', methods=['GET'])
def get_product_price():
    name = request.args.get('name')
    if not name:
        return json.dumps({"status": 3, "price": "NULL"}), 200

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT price FROM products WHERE name = ?", (name,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return json.dumps({"status": 1, "price": str(round(row[0], 2))}), 200
        else:
            return json.dumps({"status": 3, "price": "NULL"}), 200
    except:
        return json.dumps({"status": 3, "price": "NULL"}), 200