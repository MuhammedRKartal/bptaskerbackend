import os
import mariadb
import binascii
from dotenv import load_dotenv
from flask import jsonify
from werkzeug.security import generate_password_hash

from .AppHandler import AppHandler

load_dotenv()

auth_token = os.getenv("AUTH_TOKEN")


class AuthHandler:

    @classmethod
    def verify(cls, request):
        data = request.json
        email = data.get("email")
        username = data.get("username")
        # CHANGE MADE : AuthHandler :: verify :: added password field, assumed from data
        password = data.get("password")
        verification_code = data.get("verification_code")
        headers = request.headers

        auth = headers["auth_token"]

        if not username or not verification_code or not email:
            return (
                jsonify({"error": "Missing username or verification_code or email"}),
                400,
            )
        if not auth or (auth and auth != auth_token):
            return jsonify({"error": "Invalid auth token"}), 400

        # we won't store the plaintext password. hash it
        hashed_password = generate_password_hash(password)

        # token to be used for session purposes
        token = binascii.hexlify(os.urandom(24)).decode()

        connection = AppHandler.connection
        # check to see if there's an active code for this user

        if connection:
            cursor = connection.cursor()
            query = "INSERT INTO users (user_id, username,email, password) VALUES (%s, %s, %s,%s);"
            try:
                cursor.execute(query, (token, username, email, hashed_password))
                connection.commit()
            except mariadb.IntegrityError as err:
                # This block catches an IntegrityError, which includes violations of UNIQUE constraints
                # url = "http://wowtasker.io/changepassword"

                # # Parameters to be sent in the query string
                # params = {
                #     "username": username,
                #     "password":password,
                #     "auth": "I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz"
                # }

                # # Making a GET request to the endpoint with the parameters
                # response = requests.get(url, params=params)

                return jsonify({"error": "Username already exists"}), 400
            except mariadb.Error as err:
                # Handle other potential errors
                print("Something went wrong: {}".format(err))
                return jsonify({"error": "Database error"}), 500
            finally:
                cursor.close()
            return jsonify({"message": "User added successfully", "token": token}), 200
        else:
            return jsonify({"error": "Failed to connect to the database"}), 500
