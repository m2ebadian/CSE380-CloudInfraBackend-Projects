import sqlite3
import json
import hmac
import base64
import hashlib
import requests
from flask import Flask, request

app = Flask(__name__)

def get_secret_key():
    try:
        with open("key.txt", "r") as f:
            return f.read().strip()
    except Exception:
        return None

def verify_jwt(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature = parts
        secret_key = get_secret_key()
        if not secret_key:
            return None

        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))
        username = payload.get('username')

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()

        if computed_signature != signature:
            return None

        return username
    except:
        return None

@app.route('/order', methods=['POST'])
def place_order():
    try:
        jwt_token = request.headers.get('Authorization')
        if not jwt_token:
            return json.dumps({"status": 2, "cost": "NULL"}), 200

        username = verify_jwt(jwt_token)
        if not username:
            return json.dumps({"status": 2, "cost": "NULL"}), 200

        order_data = request.form.get("order")
        if not order_data:
            return json.dumps({"status": 2, "cost": "NULL"}), 200

        order = json.loads(order_data)
        total_cost = 0.0

        for item in order:
            name = item.get("product")
            quantity = item.get("quantity")

            if not name or not quantity:
                return json.dumps({"status": 3, "cost": "NULL"}), 200

            response = requests.get("http://products:5000/get_product_price", params={"name": name})
            if response.status_code != 200:
                return json.dumps({"status": 3, "cost": "NULL"}), 200

            product_info = response.json()
            if product_info["status"] != 1:
                return json.dumps({"status": 3, "cost": "NULL"}), 200

            price = product_info["price"]
            total_cost += float(price) * int(quantity)

        return json.dumps({"status": 1, "cost": "%.2f" % total_cost}), 200

    except:
        return json.dumps({"status": 3, "cost": "NULL"}), 200


@app.route('/clear', methods=['GET'])
def clear_orders():
    return {}, 200