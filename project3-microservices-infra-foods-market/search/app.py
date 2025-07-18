import json
import hmac
import base64
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
        secret_key = get_secret_key()
        if not secret_key:
            return None

        header_b64, payload_b64, signature = jwt_token.split('.')
        padded_payload = payload_b64 + '=' * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))

        username = payload.get("username")
        if not username:
            return None

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(secret_key.encode('utf-8'), message, digestmod='sha256').hexdigest()
        if expected_sig != signature:
            return None

        return username
    except:
        return None

@app.route("/search", methods=["GET"])
def search_product():
    jwt_token = request.headers.get("Authorization")
    if not jwt_token:
        return json.dumps({"status": 2, "data": "NULL"}), 200

    username = verify_jwt(jwt_token)
    if not username:
        return json.dumps({"status": 2, "data": "NULL"}), 200

    product_name = request.args.get("product_name")
    category = request.args.get("category")

    if product_name:
        r = requests.get(f"http://products:5000/_internal_get_product_by_name", params={"name": product_name})
        if r.status_code != 200 or not r.json():
            return json.dumps({"status": 3, "data": "NULL"}), 200
        products = r.json()

        try:
            requests.post(
                "http://logs:5000/log",
                data={"event": "search", "user": username, "name": product_name},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        except:
            pass

    elif category:
        r = requests.get(f"http://products:5000/_internal_get_products_by_category", params={"category": category})
        if r.status_code != 200 or not r.json():
            return json.dumps({"status": 3, "data": "NULL"}), 200
        products = r.json()

        try:
            requests.post(
                "http://logs:5000/log",
                data={"event": "search", "user": username, "name": category},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        except:
            pass

    else:
        return json.dumps({"status": 3, "data": "NULL"}), 200

    enriched_products = []
    for p in products:
        r_log = requests.get("http://logs:5000/_internal_last_modifier", params={"product_name": p["product_name"]})
        if r_log.status_code == 200:
            last_mod = r_log.json().get("last_mod", "unknown")
        else:
            last_mod = "unknown"

        enriched_products.append({
            "product_name": p["product_name"],
            "price": p["price"],
            "category": p["category"],
            "last_mod": last_mod
        })

    return json.dumps({"status": 1, "data": enriched_products}), 200

@app.route("/clear", methods=["GET"])
def clear():
    return {}, 200
    