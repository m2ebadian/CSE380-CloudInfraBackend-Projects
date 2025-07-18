import sqlite3
import os
from flask import Flask, request
import hashlib
import json
import hmac
import base64



app = Flask(__name__)
db_name = "project1.db"
sql_file = "project1.sql"
db_flag = False

def create_db():
    conn = sqlite3.connect(db_name)
    
    with open(sql_file, 'r') as sql_startup:
    	init_db = sql_startup.read()
         
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	return conn

@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM users;")
	result = cursor.fetchall()
	conn.close()

	return result

@app.route('/test_get', methods=(['GET', 'POST']))
def test_get():
	result = request.args.get('numbers')

	return result

@app.route('/test_post', methods=(['POST']))
def test_post():
	result = request.form

	return result

@app.route('/clear', methods=['GET'])
def clear_database():
    """Handles the clearing of the database by deleting the .db file and recreating it."""
    try:
        
        conn = sqlite3.connect(db_name)
        conn.close()

        
        if os.path.exists(db_name):
            try:
                os.remove(db_name)
            except Exception as e:
                return json.dumps({"error": f"Failed to delete DB: {str(e)}"}), 500

        create_db()

        return {}, 200
    
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500
    finally:
        if conn:
            conn.close()
            
	
@app.route('/create_user', methods=['POST'])
def create_user():
    """user creation with password validation and hashing."""
    try:
       
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email_address = request.form.get('email_address')
        password = request.form.get('password')
        salt = request.form.get('salt')

        if not all([first_name, last_name, username, email_address, password, salt]):
            return json.dumps({"status": 4, "pass_hash": "NULL"}), 200

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # seeing if the username exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return json.dumps({"status": 2, "pass_hash": "NULL"}), 200

        # seeing if the email address exists already
        cursor.execute("SELECT id FROM users WHERE email_address = ?", (email_address,))
        if cursor.fetchone():
            conn.close()
            return json.dumps({"status": 3, "pass_hash": "NULL"}), 200

        # use the helper function I made to make sure the password is valid
        if not is_valid_password(password, first_name, last_name, username):
            conn.close()
            return json.dumps({"status": 4, "pass_hash": "NULL"}), 200

        
        password_hash = hash_password(password, salt)

        # Insert new user into database
        cursor.execute(
            "INSERT INTO users (first_name, last_name, username, email_address, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?)",
            (first_name, last_name, username, email_address, password_hash, salt)
        )

        # Store the initial password in password_history
        cursor.execute(
            "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
            (cursor.lastrowid, password_hash)  
        )
        conn.commit()
        conn.close()

        # if everything is correct, return the status code 1 and the password hash
        return json.dumps({"status": 1, "pass_hash": password_hash}), 200

    except Exception:
        return json.dumps({"status": 4, "pass_hash": "NULL"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    """Handles user login, verifies credentials, and returns a JWT token if successful."""
    try:
        # Get username and password from request
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return json.dumps({"status": 2, "jwt": "NULL"}), 200 

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # get the password hash and salt for the user
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

        conn.close()

        if not user_data:
            return json.dumps({"status": 2, "jwt": "NULL"}), 200

        stored_hash, salt = user_data
        computed_hash = hash_password(password, salt)

        # Compare computed hash with stored hash
        if computed_hash != stored_hash:
            return json.dumps({"status": 2, "jwt": "NULL"}), 200  

        # Generate JWT token on successful authentication
        jwt_token = generate_jwt(username)
        return json.dumps({"status": 1, "jwt": jwt_token}), 200

    except Exception as e:
        return json.dumps({"status": 2, "jwt": "NULL"}), 500
    
    finally:
        if conn:
            conn.close()
    

@app.route('/update', methods=['POST'])
def update_user():
    """Handles updating a user's username or password."""
    try:
        # Extract parameters from the request
        username = request.form.get('username')
        new_username = request.form.get('new_username')
        password = request.form.get('password')
        new_password = request.form.get('new_password')
        jwt_token = request.form.get('jwt')

        # Ensure JWT is provided
        if not jwt_token or not username:
            return json.dumps({"status": 3}), 200  

        # Verify JWT securely
        try:
            if not verify_jwt(jwt_token, username):
                return json.dumps({"status": 3}), 200 
        except Exception:
            return json.dumps({"status": 3}), 200  

        # Ensure only one field is updated at a time
        if (new_username and new_password) or (not new_username and not new_password):
            return json.dumps({"status": 2}), 200  

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

         # Get user_id for reference
        cursor.execute("SELECT id, password_hash, salt, first_name, last_name FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

        if not user_data:
            conn.close()
            return json.dumps({"status": 2}), 200  

        user_id, stored_hash, salt, first_name, last_name = user_data

        # username change
        if new_username:
            # Ensure new username is unique
            cursor.execute("SELECT id FROM users WHERE username = ?", (new_username,))
            if cursor.fetchone():
                conn.close()
                return json.dumps({"status": 2}), 200  

            # Update the username
            cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
            conn.commit()
            conn.close()
            return json.dumps({"status": 1}), 200  

        # password change
        if new_password:
            computed_hash = hash_password(password, salt)

            # Verify old password
            if computed_hash != stored_hash:
                conn.close()
                return json.dumps({"status": 2}), 200  

            # make sure password is valid
            if not is_valid_password(new_password, first_name, last_name, username):
                conn.close()
                return json.dumps({"status": 2}), 200  

            # Check password history using user_id
            new_password_hash = hash_password(new_password, salt)
            cursor.execute("SELECT 1 FROM password_history WHERE user_id = ? AND password_hash = ?", (user_id, new_password_hash))
            if cursor.fetchone():
                conn.close()
                return json.dumps({"status": 2}), 200  #

            # Update password and store in password history
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
            cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)", (user_id, new_password_hash))
            conn.commit()
            conn.close()

            return json.dumps({"status": 1}), 200 

    except Exception as e:
        return json.dumps({"status": 2}), 500
    
    finally:
        if conn:
            conn.close() 
    




@app.route('/view', methods=['POST'])
def view_user():
    """Handles user information retrieval."""
    
    try:
        # Extract JWT from request
        jwt_token = request.form.get('jwt')

        if not jwt_token:
            return json.dumps({"status": 2, "data": "NULL"}), 200  

        # Verify JWT and extract username
        try:
            secret_key = get_secret_key()
            header_b64, payload_b64, signature = jwt_token.split('.')

           
            def add_padding(base64_str):
                return base64_str + "=" * (-len(base64_str) % 4)

            payload_decoded = json.loads(base64.urlsafe_b64decode(add_padding(payload_b64)).decode('utf-8'))
            username = payload_decoded.get("username")

            
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()

           
            if computed_signature.lower() != signature.lower() or payload_decoded.get("access") != "True":
                return json.dumps({"status": 2, "data": "NULL"}), 200  

        except Exception:
            return json.dumps({"status": 2, "data": "NULL"}), 200  

        # Retrieve user information
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT username, email_address, first_name, last_name FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        # Return user data
        if user_data:
            return json.dumps({
                "status": 1,
                "data": {
                    "username": user_data[0],
                    "email_address": user_data[1],
                    "first_name": user_data[2],
                    "last_name": user_data[3]
                }
            }), 200
        else:
            return json.dumps({"status": 2, "data": "NULL"}), 200 

    except Exception as e:
        return json.dumps({"status": 2, "data": "NULL", "error": str(e)}), 500
    
    finally:
        if conn:
            conn.close()  


def is_valid_password(password, first_name, last_name, username):


    # length requirement
    if len(password) < 8:
        return False

    # at least one lowercase letter
    if not any(c.islower() for c in password):
        return False

    # at least one uppercase letter
    if not any(c.isupper() for c in password):
        return False

    # at least one digit
    if not any(c.isdigit() for c in password):
        return False

    #
    lower_password = password.lower()
    if first_name.lower() in lower_password or last_name.lower() in lower_password or username.lower() in lower_password:
        return False

    return True  




def hash_password(password, salt):

    salted_password = password + salt
    hashed = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()

    return hashed



def get_secret_key():
    try:
        with open("key.txt", "r") as f:
            return f.read().strip()
    except Exception:
        return None
    

def base64url_encode(data):
    """Encodes data in Base64 URL-safe format and ensures correct padding."""
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    
    return encoded + ('=' * (4 - len(encoded) % 4)) if len(encoded) % 4 != 0 else encoded

def generate_jwt(username):
    """Generates a JWT with Base64 URL encoding and HMAC-SHA256 signature."""
    secret_key = get_secret_key()
    if not secret_key:
        return "NULL"

    
    header = json.dumps({"alg": "HS256", "typ": "JWT"}).encode('utf-8')
    encoded_header = base64url_encode(header)

    
    payload = json.dumps({"username": username, "access": "True"}).encode('utf-8')
    encoded_payload = base64url_encode(payload)

    
    message = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()

    
    jwt_token = f"{encoded_header}.{encoded_payload}.{signature}"
    return jwt_token


def verify_jwt(token, expected_username):
    try:
        secret_key = get_secret_key()
        if not secret_key:
            return False

        # Split the JWT
        header_b64, payload_b64, signature = token.split('.')

        
        def add_padding(base64_str):
            return base64_str + "=" * (-len(base64_str) % 4)

        header_decoded = json.loads(base64.urlsafe_b64decode(add_padding(header_b64)).decode('utf-8'))
        payload_decoded = json.loads(base64.urlsafe_b64decode(add_padding(payload_b64)).decode('utf-8'))

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()

        
        if computed_signature.lower() != signature.lower():
            return False  

        
        if payload_decoded.get("username") != expected_username or payload_decoded.get("access") != "True":
            return False  

        return True  

    except Exception:
        return False