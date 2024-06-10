# /users/register.py

import binascii
import os
import random
from flask import jsonify
from werkzeug.security import generate_password_hash
import mariadb

from db_connection import DatabaseConnector
db_connector = DatabaseConnector()

from .mail import send_verification_email  # Assuming you have a module for sending emails

def perform_registration(data, headers):
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    auth = headers.get("auth_token")

    if not username or not password or not email:
        return jsonify({"error": "Missing username, password, or email"}), 400
    if not auth or auth != "expected_auth_token":  # You need to define the expected token
        return jsonify({"error": "Invalid auth token"}), 403
    
    disallowed_words = ["banned_word1", "banned_word2"]  # Example banned words
    if any(word in username.lower() for word in disallowed_words):
        return jsonify({"error": "Username contains reserved words"}), 400
    
    hashed_password = generate_password_hash(password)
    token = binascii.hexlify(os.urandom(24)).decode()
    verification_code = "{:06d}".format(random.randint(100000, 999999))

    # Database operations
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users (user_id, email, username, password) VALUES (%s, %s, %s, %s);", (token, email, username, hashed_password))
        connection.commit()
        cursor.execute("DELETE FROM user_registration WHERE email = %s", (email,))
        cursor.execute("INSERT INTO user_registration (email, verification_code, password) VALUES (%s, %s, %s)", (email, verification_code, password))
        connection.commit()
    except mariadb.IntegrityError:
        # Handle duplicate user registration, etc.
        return jsonify({"error": "User already exists"}), 400
    except mariadb.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        connection.close()
    
    send_verification_email(email, verification_code, username)
    return jsonify({"email": email, "username": username, "verification_code": verification_code}), 200