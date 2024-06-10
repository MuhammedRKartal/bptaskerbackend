import binascii
import os

import mariadb
import jwt
from dotenv import load_dotenv
from flask import jsonify
from werkzeug.security import generate_password_hash

from .AppHandler import AppHandler
from .UsersHandler import UsersHandler

load_dotenv()

auth_token = os.getenv("AUTH_TOKEN")


class WebHandler:

    @classmethod
    def addUser(cls, request):
        username = request.args.get("username")
        password = request.args.get("password")
        auth = request.args.get("auth")
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400
        if not auth or (auth and auth != auth_token):
            return jsonify({"error": "Invalid auth token"}), 400

        # we won't store the plaintext password. hash it
        hashed_password = generate_password_hash(password)

        # token to be used for session purposes
        token = binascii.hexlify(os.urandom(24)).decode()

        connection = AppHandler.connection

        if not connection:
            return jsonify({"error": "Failed to connect to the database"}), 500
        cursor = connection.cursor()
        query = "INSERT INTO users (user_id, username, password) VALUES (%s, %s, %s);"
        try:
            # CHANGE MADE : WebHandler :: addUser :: email didn't have default value or allowed default in table
            # so I turned on allow null for email
            cursor.execute(query, (token, username, hashed_password))
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

    @classmethod
    def currentUser(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 401

        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception(
                    "TokensHandler :: refreshTokensIfNeeded :: Env vars not found"
                )
            # Decode the refresh token to get the user_id
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            token_type = payload.get("token_type")

            if not token_type or token_type != "refresh":
                return jsonify({"error": "Invalid refresh token"}), 401
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401

            return UsersHandler.buildUserObject(user_id)
        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
