import sqlite3
import os
from flask import Flask, request
import hashlib
import json
import hmac
import base64



app = Flask(__name__)
db_name = "project2.db"
sql_file = "project2.sql"
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
    """Handles user creation with password validation, hashing, and role flags."""
    conn = None
    try:
        # Collect form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email_address = request.form.get('email_address')
        password = request.form.get('password')
        salt = request.form.get('salt')

        moderator = request.form.get('moderator', 'False')
        critic = request.form.get('critic', 'False')

        # Validate required fields
        if not all([first_name, last_name, username, email_address, password, salt]):
            return json.dumps({"status": 4, "pass_hash": "NULL"}), 200

        # Convert moderator/critic flags to integers (0 or 1)
        is_moderator = 1 if str(moderator).lower() == 'true' else 0
        is_critic = 1 if str(critic).lower() == 'true' else 0

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Check for existing username or email
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return json.dumps({"status": 2, "pass_hash": "NULL"}), 200

        cursor.execute("SELECT id FROM users WHERE email_address = ?", (email_address,))
        if cursor.fetchone():
            return json.dumps({"status": 3, "pass_hash": "NULL"}), 200

        # Validate password
        if not is_valid_password(password, first_name, last_name, username):
            return json.dumps({"status": 4, "pass_hash": "NULL"}), 200

        # Hash and store the password
        password_hash = hash_password(password, salt)

        cursor.execute("""
            INSERT INTO users (first_name, last_name, username, email_address, moderator, critic, password_hash, salt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (first_name, last_name, username, email_address, is_moderator, is_critic, password_hash, salt))

        user_id = cursor.lastrowid

        # Save to password history
        cursor.execute(
            "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
            (user_id, password_hash)
        )

        conn.commit()
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
    conn = None
    try:
        jwt_token = request.form.get('jwt')
        if not jwt_token:
            return json.dumps({"status": 2, "data": "NULL"}), 200  

        secret_key = get_secret_key()
        if not secret_key:
            return json.dumps({"status": 2, "data": "NULL"}), 200 

        # Split JWT into parts
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return json.dumps({"status": 2, "data": "NULL"}), 200 

        header_b64, payload_b64, signature = parts

        
        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))

        if payload.get("access") != "True":
            return json.dumps({"status": 2, "data": "NULL"}), 200

        username = payload.get("username")
        if not username:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        
        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()

        if computed_signature != signature:
            return json.dumps({"status": 2, "data": "NULL"}), 200  

        
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT username, email_address, first_name, last_name FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()

        if not row:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        return json.dumps({
            "status": 1,
            "data": {
                "username": row[0],
                "email_address": row[1],
                "first_name": row[2],
                "last_name": row[3]
            }
        }), 200

    except Exception:
        return json.dumps({"status": 2, "data": "NULL"}), 200

    finally:
        if conn:
            conn.close() 





@app.route('/create_movie', methods=['POST'])
def create_movie():
    """Allows a moderator to create a movie entry with optional genres."""
    conn = None
    try:
       
        jwt_token = request.headers.get('Authorization')
        if not jwt_token:
            return json.dumps({"status": 2}), 200

        
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return json.dumps({"status": 2}), 200

        header_b64, payload_b64, signature = parts
        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))

        if payload.get("moderator") != "True" or not payload.get("username"):
            return json.dumps({"status": 2}), 200

       
        secret_key = get_secret_key()
        if not secret_key:
            return json.dumps({"status": 2}), 200

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
        if computed_signature != signature:
            return json.dumps({"status": 2}), 200

        
        title = request.form.get('title')
        synopsis = request.form.get('synopsis')
        movie_id = request.form.get('movie_id')
        genre_json_str = request.form.get('genre')

        if not all([title, synopsis, movie_id]):
            return json.dumps({"status": 2}), 200

        movie_id = int(movie_id)

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        
        cursor.execute("INSERT INTO movies (movie_id, title, synopsis) VALUES (?, ?, ?)", (movie_id, title, synopsis))

        # if genres were provided, make sure each one exists in the genres table
        # if it's a new genre, insert it
        # then link the genre to the movie in the movie_genres table
        if genre_json_str:
            genre_dict = json.loads(genre_json_str)
            for key in genre_dict:
                genre_name = genre_dict[key].strip()

                
                cursor.execute("SELECT genre_id FROM genres WHERE name = ?", (genre_name,))
                genre_row = cursor.fetchone()

                if genre_row:
                    genre_id = genre_row[0]
                else:
                    cursor.execute("INSERT INTO genres (name) VALUES (?)", (genre_name,))
                    genre_id = cursor.lastrowid

                
                cursor.execute("INSERT INTO movie_genres (movie_id, genre_id) VALUES (?, ?)", (movie_id, genre_id))

        conn.commit()
        return json.dumps({"status": 1}), 200

    except Exception:
        return json.dumps({"status": 2}), 200

    finally:
        if conn:
            conn.close()







@app.route('/review', methods=['POST'])
def review_movie():
    """Allows an authenticated user to leave a review for a movie."""
    conn = None
    try:
        
        jwt_token = request.headers.get('Authorization')
        if not jwt_token:
            return json.dumps({"status": 2}), 200

        parts = jwt_token.split('.')
        if len(parts) != 3:
            return json.dumps({"status": 2}), 200

        header_b64, payload_b64, signature = parts
        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))

        username = payload.get("username")
        if not username:
            return json.dumps({"status": 2}), 200

        
        secret_key = get_secret_key()
        if not secret_key:
            return json.dumps({"status": 2}), 200

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()

        if computed_signature != signature:
            return json.dumps({"status": 2}), 200

        
        rating = request.form.get('rating')
        text = request.form.get('text')
        movie_id = request.form.get('movie_id')
        review_id = request.form.get('review_id')

        if not all([rating, text, movie_id, review_id]):
            return json.dumps({"status": 2}), 200

        rating = int(rating)
        movie_id = int(movie_id)
        review_id = int(review_id)

        if rating < 0 or rating > 5:
            return json.dumps({"status": 2}), 200

        
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        if not user_row:
            return json.dumps({"status": 2}), 200
        user_id = user_row[0]

        
        cursor.execute("SELECT 1 FROM movies WHERE movie_id = ?", (movie_id,))
        if not cursor.fetchone():
            return json.dumps({"status": 2}), 200

        
        cursor.execute("INSERT INTO reviews (review_id, movie_id, user_id, rating, text) VALUES (?, ?, ?, ?, ?)", (review_id, movie_id, user_id, rating, text))

        conn.commit()
        return json.dumps({"status": 1}), 200

    except Exception:
        return json.dumps({"status": 2}), 200
    finally:
        if conn:
            conn.close()






















@app.route('/view_movie/<int:movie_id>', methods=['GET'])
def view_movie(movie_id):
    conn = None
    try:
        
        jwt_token = request.headers.get('Authorization')
        if not jwt_token:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        parts = jwt_token.split('.')
        if len(parts) != 3:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        header_b64, payload_b64, signature = parts
        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))

        username = payload.get("username")
        if not username:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        secret_key = get_secret_key()
        if not secret_key:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
        if computed_signature != signature:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        
        fields = request.args
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        
        cursor.execute("SELECT title, synopsis FROM movies WHERE movie_id = ?", (movie_id,))
        movie = cursor.fetchone()
        if not movie:
            return json.dumps({"status": 2, "data": "NULL"}), 200


        # add title and synopsis to result if they were requested
        result = {}
        if 'title' in fields:
            result['title'] = movie[0]
        if 'synopsis' in fields:
            result['synopsis'] = movie[1]

        # get genres for the movie if 'genre' was included in the query
        if 'genre' in fields:
            cursor.execute('SELECT g.name FROM genres g JOIN movie_genres mg ON g.genre_id = mg.genre_id WHERE mg.movie_id = ?', (movie_id,))
            genres = [row[0] for row in cursor.fetchall()]
            result['genre'] = genres


        # gather ratings and split them into critic and audience based on user role
        if 'critic' in fields or 'audience' in fields:
            cursor.execute('SELECT r.rating, u.critic FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.movie_id = ?', (movie_id,))
            critics = []
            audience = []
            for rating, is_critic in cursor.fetchall():
                (critics if is_critic else audience).append(rating)


            # calculate average ratings and round to 2 decimals, or return "0.00" if no reviews
            if 'critic' in fields:
                result['critic'] = "{:.2f}".format(sum(critics)/len(critics)) if critics else "0.00"
            if 'audience' in fields:
                result['audience'] = "{:.2f}".format(sum(audience)/len(audience)) if audience else "0.00"

        # if reviews are requested, get them and format as a list of dictionaries
        if 'reviews' in fields:
            cursor.execute('SELECT u.username, r.rating, r.text FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.movie_id = ?', (movie_id,))
            reviews = [{"user": row[0], "rating": str(row[1]), "text": row[2]} for row in cursor.fetchall()]
            result['reviews'] = reviews

        return json.dumps({"status": 1, "data": result}), 200

    except Exception:
        return json.dumps({"status": 2, "data": "NULL"}), 200

    finally:
        if conn:
            conn.close()








@app.route('/search', methods=['GET'])
def search_movies():
    """Handles movie search by genre or feed."""
    conn = None
    try:
        jwt_token = request.headers.get('Authorization')
        if not jwt_token:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        header_b64, payload_b64, signature = parts
        secret_key = get_secret_key()
        if not secret_key:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))
        username = payload.get('username')
        if not username:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        computed_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
        if computed_signature != signature:
            return json.dumps({"status": 2, "data": "NULL"}), 200

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        
        genre = request.args.get('genre')
        feed = request.args.get('feed')
        
        # check if user is searching by genre or feed, and get the right movie_ids
        if genre:
            cursor.execute("SELECT m.movie_id FROM movies m JOIN movie_genres mg ON m.movie_id = mg.movie_id JOIN genres g ON mg.genre_id = g.genre_id WHERE g.name = ?" , (genre,))
        else:
            cursor.execute("SELECT movie_id FROM movies ORDER BY created_at DESC LIMIT 5")

        movie_ids = [row[0] for row in cursor.fetchall()]
        result_data = {}


        # for each movie, get its title, synopsis, genres, and reviews (split by critic and audience)
        for movie_id in movie_ids:
            
            cursor.execute("SELECT title, synopsis FROM movies WHERE movie_id = ?", (movie_id,))
            title, synopsis = cursor.fetchone()

            
            cursor.execute("SELECT g.name FROM genres g JOIN movie_genres mg ON g.genre_id = mg.genre_id WHERE mg.movie_id = ?", (movie_id,))
            genres = [row[0] for row in cursor.fetchall()]

           
            cursor.execute("SELECT u.username, r.rating, r.text, u.critic FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.movie_id = ? ", (movie_id,))

            reviews = []
            critic_sum, critic_count = 0, 0
            audience_sum, audience_count = 0, 0
            

            # loop through reviews and separate critic and audience ratings to calculate averages
            for user, rating, text, is_critic in cursor.fetchall():
                reviews.append({"user": user, "rating": str(rating), "text": text})
                if is_critic:
                    critic_sum += rating
                    critic_count += 1
                else:
                    audience_sum += rating
                    audience_count += 1

            critic_avg = f"{(critic_sum / critic_count):.2f}" if critic_count > 0 else "0.00"
            audience_avg = f"{(audience_sum / audience_count):.2f}" if audience_count > 0 else "0.00"

            result_data[movie_id] = {
                "title": title,
                "synopsis": synopsis,
                "genre": genres,
                "critic": critic_avg,
                "audience": audience_avg,
                "reviews": reviews
            }

        return json.dumps({"status": 1, "data": result_data}), 200

    except Exception:
        return json.dumps({"status": 2, "data": "NULL"}), 200

    finally:
        if conn:
            conn.close()






@app.route('/delete', methods=['POST'])
def delete():
    conn = None
    try:
        conn = sqlite3.connect(db_name)
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()

        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return json.dumps({"status": 2}), 200

        
        # decode and verify the JWT to make sure the user is who they say they are
        try:
            header_b64, payload_b64, signature = auth_header.split('.')
            padded_payload = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded_payload.encode()).decode('utf-8'))
            jwt_username = payload.get('username')
            is_moderator = payload.get('moderator') == 'True'
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_key = get_secret_key()
            expected_signature = hmac.new(secret_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
            if expected_signature != signature:
                return json.dumps({"status": 2}), 200
        except Exception:
            return json.dumps({"status": 2}), 200

        username_to_delete = request.form.get('username')
        review_id_to_delete = request.form.get('review_id')


        # if deleting a user, make sure it's the same user that's logged in, then delete
        if username_to_delete:
            if username_to_delete != jwt_username:
                return json.dumps({"status": 2}), 200
            cursor.execute("DELETE FROM users WHERE username = ?", (username_to_delete,))
            conn.commit()
            return json.dumps({"status": 1}), 200

        # if deleting a review, make sure it's the same user that made the review or a moderator
        # then delete
        elif review_id_to_delete:
            cursor.execute("SELECT user_id FROM reviews WHERE review_id = ?", (review_id_to_delete,))
            result = cursor.fetchone()
            if not result:
                return json.dumps({"status": 2}), 200

            review_owner_id = result[0]
            cursor.execute("SELECT id FROM users WHERE username = ?", (jwt_username,))
            user_result = cursor.fetchone()
            if not user_result:
                return json.dumps({"status": 2}), 200

            requester_id = user_result[0]

            if requester_id != review_owner_id and not is_moderator:
                return json.dumps({"status": 2}), 200

            cursor.execute("DELETE FROM reviews WHERE review_id = ?", (review_id_to_delete,))
            conn.commit()
            return json.dumps({"status": 1}), 200

        return json.dumps({"status": 2}), 200

    except Exception:
        return json.dumps({"status": 2}), 500

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
    """Generates a JWT that optionally includes moderator field."""
    secret_key = get_secret_key()
    if not secret_key:
        return "NULL"

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT moderator FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    is_moderator = row[0] == 1 if row else False

    header = json.dumps({"alg": "HS256", "typ": "JWT"}).encode('utf-8')
    encoded_header = base64url_encode(header)

    
    if is_moderator:
        payload = json.dumps({"username": username, "moderator": "True"}).encode('utf-8')
    else:
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