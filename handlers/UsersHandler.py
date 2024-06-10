import os
import random
import binascii
import mariadb
import jwt
from dotenv import load_dotenv
from flask import jsonify
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash

from .AppHandler import AppHandler
from .EmailHandler import EmailHandler
from .LicensesHandler import LicensesHandler
from .TokensHandler import TokensHandler
from .OrdersHandler import OrdersHandler

load_dotenv()

auth_token = os.getenv("AUTH_TOKEN")


class UsersHandler:

    @classmethod
    def deleteUser(cls, request):
        data = request.json
        username = data.get("username")
        email = data.get("email")

        headers = request.headers
        print(request.headers)
        auth = headers.get("auth_token")

        if not username and not email:
            return jsonify({"error": "Missing username or email"}), 400
        if not auth or auth != auth_token:
            print(f"{auth} :: {auth_token}")
            return jsonify({"error": "Invalid auth token"}), 403

        connection = AppHandler.connection
        if not connection:
            return jsonify({"error": "Failed to connect to the database"}), 500

        cursor = connection.cursor()

        try:
            # If username is not provided, fetch it using the email
            if not username:
                username_query = "SELECT username FROM users WHERE email = %s"
                cursor.execute(username_query, (email,))
                username_record = cursor.fetchone()
                if username_record:
                    username = username_record[0]
                else:
                    return jsonify({"error": "Email not found"}), 404

            verification_code = "{:06d}".format(random.randint(100000, 999999))
            delete_verification_query = "DELETE FROM delete_user WHERE email = %s"
            insert_verification_query = (
                "INSERT INTO delete_user (email, verification_code) VALUES (%s, %s)"
            )

            # Insert verification code
            cursor.execute(delete_verification_query, (email,))
            connection.commit()

            cursor.execute(insert_verification_query, (email, verification_code))
            connection.commit()

        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Database error"}), 500
        finally:
            cursor.close()
        EmailHandler.sendDeleteUserVerificationEmail(email, username, verification_code)
        return (
            jsonify(
                {
                    "email": email,
                    "username": username,
                    "verification_code": verification_code,
                }
            ),
            200,
        )

    @classmethod
    def confirmDeleteUser(cls, request):
        data = request.json
        username = data.get("username")
        email = data.get("email")
        verification_code = data.get("verification_code")

        headers = request.headers
        auth = headers.get(
            "auth_token"
        )  # Use .get to avoid KeyError if "auth_token" is missing
        if not auth or auth != auth_token:
            return (
                jsonify({"error": "Invalid auth token"}),
                403,
            )  # 403 Forbidden for auth issues

        if not email and not username or not verification_code:
            return (
                jsonify({"error": "Missing email or username, or verification code"}),
                400,
            )
        cursor = None

        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception(
                    "UsersHandler :: confirmDeleteUser :: connection is None"
                )
            cursor = connection.cursor()

            # If username is not provided, fetch it using the email
            if not username:
                username_query = "SELECT username FROM users WHERE email = %s"
                cursor.execute(username_query, (email,))
                username_record = cursor.fetchone()
                if username_record:
                    username = username_record[0]
                else:
                    return jsonify({"error": "Email not found"}), 404

            # Query to check if the email and verification_code match and the code is not older than 3 minutes
            verification_query = """
            SELECT * FROM delete_user
            WHERE email = %s AND verification_code = %s
            AND created_at >= NOW() - INTERVAL 3 MINUTE
            """
            cursor.execute(verification_query, (email, verification_code))
            if cursor.fetchone():
                # Delete the user from the users table
                delete_user_query = "DELETE FROM users WHERE email = %s"
                cursor.execute(delete_user_query, (email,))
                connection.commit()
                EmailHandler.sendAccountDeletedEmail(email, username)
                return (
                    jsonify(
                        {
                            "status": "OK",
                            "message": "Successfully deleted user!",
                            "email": email,
                        }
                    ),
                    200,
                )
            else:
                return (
                    jsonify(
                        {
                            "error": "Invalid email or verification code, or code has expired"
                        }
                    ),
                    400,
                )
        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Database error"}), 500
        finally:
            if cursor:
                cursor.close()

    @classmethod
    def buildUserObject(cls, user_id, additional_data=None, refresh=True):
        # Fetch user details from the database
        connection = AppHandler.connection
        if connection is None:
            return jsonify(
                {"error": "UsersHandler :: buildUserObject :: connection is None"}
            )

        cursor = connection.cursor()
        user_query = """
        SELECT user_id, username, email, verified, date_joined, email_allowed, eula_accepted
        FROM users WHERE user_id = %s
        """
        cursor.execute(user_query, (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        (
            user_id,
            username,
            email,
            verified,
            date_joined,
            email_allowed,
            eula_accepted,
        ) = user

        # Create response with the user information
        user_info = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "verified": bool(verified),
            "date_joined": date_joined.strftime("%Y-%m-%d %H:%M:%S"),
            "email_allowed": bool(email_allowed),
            "eula_accepted": bool(eula_accepted),
        }

        # Merge the user_info and the additional_data
        if additional_data is not None:
            user_info = {**user_info, **additional_data}

        response = jsonify(user_info)

        if refresh:
            ACCESS_TOKEN_EXPIRES_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES")
            REFRESH_TOKEN_EXPIRES_DAYS = os.getenv("REFRESH_TOKEN_EXPIRES_DAYS")
            if (ACCESS_TOKEN_EXPIRES_MINUTES is None) or (
                REFRESH_TOKEN_EXPIRES_DAYS is None
            ):
                raise Exception("UsersHandler :: buildUserObject :: Env vars not found")
            # Generate a new access token
            access_token_expires = timedelta(
                minutes=float(ACCESS_TOKEN_EXPIRES_MINUTES)
            )
            # new_access_token = create_access_token(data={"user_id": user_id}, expires_delta=access_token_expires)

            # Optionally, generate a new refresh token
            refresh_token_expires = timedelta(days=float(REFRESH_TOKEN_EXPIRES_DAYS))
            new_refresh_token = TokensHandler.createRefreshToken(
                data={"user_id": user_id}, expires_delta=refresh_token_expires
            )
            #
            # response.headers['Authorization'] = 'Bearer ' + new_access_token
            # Set the new access token in an HTTP-only cookie
            # response.set_cookie("access_token", new_access_token, httponly=True, samesite='Strict')
            # Optionally, set the new refresh token in an HTTP-only cookie
            response.set_cookie(
                "refresh_token",
                new_refresh_token,
                secure=True,
                httponly=True,
                samesite="Strict",
                max_age=60 * 60 * 24,
            )

        return response

    @classmethod
    def allocateLicenseEndpoint(cls, request):
        headers = request.headers
        auth = headers.get("auth")
        if not auth or (auth and auth != auth_token):
            return jsonify({"error": "Invalid auth token"}), 403

        data = request.json
        user_id = data.get("user_id")
        quantity = data.get("quantity")
        if not user_id or not quantity:
            return jsonify({"error": "Missing user_id or quantity"}), 400

        result = LicensesHandler.allocateLicense(user_id, 1, quantity)
        if "error" in result:
            return jsonify(result), 400
        else:
            return jsonify(result), 200

    @classmethod
    def register(cls, request):
        data = request.json
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")

        headers = request.headers

        if not username or not password or not email:
            print("Missing username, password, or email")
            return jsonify({"error": "Missing username, password, or email"}), 400

        disallowed_words = [
            word
            for word in AppHandler.banned_username_words
            if word in username.lower()
        ]
        if disallowed_words:
            print("Username contains reserved words:", disallowed_words)
            return (
                jsonify(
                    {
                        "error": "Username contains reserved words",
                        "disallowed_words": disallowed_words,
                    }
                ),
                400,
            )
        cursor = None
        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("UsersHandler :: register :: connection is None")
            cursor = connection.cursor()

            # Check if a user with the provided email already exists
            check_user_query = "SELECT email FROM users WHERE email = %s AND verified = 1"

            cursor.execute(check_user_query, (email,))
            user = cursor.fetchone()

            if user:
                return jsonify({"error": "User with this email already exists"}), 400
            else:
                    delete_users_query = """
                    DELETE FROM users
                    WHERE email = %s
                    """
                    delete_user_registration_query = """
                    DELETE FROM user_registration
                    WHERE email = %s
                    """
                    cursor.execute(delete_users_query, (email,))
                    cursor.execute(delete_user_registration_query, (email,))

                    connection.commit()

            # ... (rest of your code)

        except mariadb.Error as err:
            print("Something went wrong:", err)
            return jsonify({"error": "Database error"}), 500
        finally:
            if cursor is not None:
                cursor.close()
        hashed_password = generate_password_hash(password)
        token = binascii.hexlify(os.urandom(24)).decode()
        verification_code = "{:06d}".format(random.randint(100000, 999999))
        delete_verification_query = "DELETE FROM user_registration WHERE email = %s"
        insert_verification_query = "INSERT INTO user_registration (email, verification_code,password) VALUES (%s, %s,%s)"

        print("Prepared queries and data")

        try:
            print("Trying to establish database connection")
            connection = AppHandler.connection
            if connection is None:
                raise Exception("UsersHandler :: register :: connection is None")
            cursor = connection.cursor()
            print("Database connection established")

            user_insert_query = "INSERT INTO users (user_id, email, username, password) VALUES (%s, %s, %s, %s);"
            print("Executing user insert query")
            cursor.execute(user_insert_query, (token, email, username, hashed_password))
            connection.commit()
            print("User insert query executed")

            print("Executing delete verification query")
            cursor.execute(delete_verification_query, (email,))
            connection.commit()
            print("Delete verification query executed")

            print("Executing insert verification query")
            cursor.execute(
                insert_verification_query, (email, verification_code, password)
            )
            connection.commit()
            print("Insert verification query executed")

        except mariadb.IntegrityError as err:
            print("Integrity error:", err)
            check_user_query = "SELECT verified FROM users WHERE email = %s"
            connection = AppHandler.connection
            if connection is None:
                raise Exception("UsersHandler :: register :: connection is None")
            cursor = connection.cursor()
            cursor.execute(check_user_query, (email,))
            user = cursor.fetchone()
            if user and user[0] == 0:  # User exists but not verified
                print("User exists but not verified")
                cursor.execute(delete_verification_query, (email,))
                cursor.execute(
                    insert_verification_query, (email, verification_code, password)
                )
                connection.commit()
                EmailHandler.sendVerificationEmail(email, verification_code, username)
                return jsonify({"email": email}), 200
                # return jsonify({"email": email, "verification_code": verification_code}), 200
            else:
                print("User already exists")
                return jsonify({"error": "User already exists"}), 400
        except mariadb.Error as err:
            print("Something went wrong:", err)
            return jsonify({"error": "Database error"}), 500
        finally:
            print("Closing database connection")
            if cursor is not None:
                cursor.close()
            print("Database connection closed")
        EmailHandler.sendVerificationEmail(email, verification_code, username)
        return jsonify({"email": email, "username": username}), 200

    @classmethod
    def confirmRegistration(cls, request):
        data = request.json
        email = data.get("email")
        verification_code = data.get("verification_code")

        if not email or not verification_code:
            return jsonify({"error": "Missing email or verification code"}), 400
        cursor = None
        try:
            connection = AppHandler.connection
            if connection:
                cursor = connection.cursor()

                # Query to check if the email and verification_code match, regardless of the code's age
                verification_query = """
                SELECT verification_code FROM user_registration
                WHERE email = %s AND verification_code = %s
                """

                cursor.execute(verification_query, (email, verification_code))
                record = cursor.fetchone()

                if not record or record[0] != verification_code:
                    return (
                        jsonify({"error": "Your verification code is incorrect."}),
                        400,
                    )

                # Query to check if the verification_code is not older than 3 minutes
                expiration_query = """
                SELECT password FROM user_registration
                WHERE email = %s AND verification_code = %s
                AND created_at >= NOW() - INTERVAL 1 MINUTE
                """
                cursor.execute(expiration_query, (email, verification_code))
                record = cursor.fetchone()

                if not record:
                    delete_query = """
                    DELETE FROM user_registration 
                    WHERE email = %s AND verification_code = %s
                    """
                    cursor.execute(delete_query, (email, verification_code))
                    connection.commit()

                    return jsonify({"error": "Your verification code is expired."}), 400

                password = record[0]

                # Update the user's verified status in the users table
                update_verified_query = "UPDATE users SET verified = 1 WHERE email = %s"
                cursor.execute(update_verified_query, (email,))
                connection.commit()

                # Retrieve the user_id and username from the users table
                user_query = "SELECT user_id, username FROM users WHERE email = %s"
                cursor.execute(user_query, (email,))
                user_record = cursor.fetchone()

                if user_record:
                    user_id, username = user_record

                    # Delete the user's record from the user_registration table
                    delete_query = "DELETE FROM user_registration WHERE email = %s"
                    cursor.execute(delete_query, (email,))
                    connection.commit()

                    # Check if a basket exists for the user
                    basket_query = "SELECT pk FROM Basket WHERE user_id = %s"
                    cursor.execute(basket_query, (user_id,))
                    basket = cursor.fetchone()

                    # If a basket doesn't exist, create one
                    if not basket:
                        create_basket_query = "INSERT INTO Basket (user_id, total_amount, total_quantity) VALUES (%s, 0, 0)"
                        cursor.execute(create_basket_query, (user_id,))
                        connection.commit()

                    return UsersHandler.buildUserObject(user_id)
                else:
                    return jsonify({"error": "User not found"}), 404
            else:
                return jsonify({"error": "Database connection failed"}), 500
        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Database error"}), 500
        finally:
            if cursor:
                cursor.close()

    @classmethod
    def changePassword(cls, request):
        data = request.json
        username = data.get("username")
        new_password = data.get("new_password")
        current_password_from_json = data.get("current_password")
        hashed_current_password = generate_password_hash(current_password_from_json)
        hashed_new_password = generate_password_hash(new_password)
        print(data)
        email = data.get("email")

        if not username and not email or not new_password:
            return jsonify({"error": "Missing username or email or password"}), 400
        cursor = None

        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("UsersHandler :: changePassword :: connection is none")
            cursor = connection.cursor()

            # Fetch the user's current password and email
            if username:
                user_query = "SELECT password, email FROM users WHERE username = %s"
                cursor.execute(user_query, (username,))
            elif email:
                user_query = "SELECT password FROM users WHERE email = %s"
                cursor.execute(user_query, (email,))
            user_record = cursor.fetchone()

            if user_record:
                current_password = user_record[0]
                # Compare the current password with the new password
                if check_password_hash(current_password, new_password):
                    return (
                        jsonify(
                            {
                                "error": "New password cannot be the same as the current password"
                            }
                        ),
                        400,
                    )
                elif not check_password_hash(
                    current_password, current_password_from_json
                ):
                    print("hashed: " + hashed_current_password)
                    print("current: " + current_password)
                    return jsonify({"error": "Current password is incorrect"}), 400
                if username and not email:
                    email = user_record[1]
            else:
                return jsonify({"error": "User not found"}), 404

            verification_code = "{:06d}".format(random.randint(100000, 999999))
            delete_verification_query = "DELETE FROM password_change WHERE email = %s"
            insert_verification_query = "INSERT INTO password_change (email, verification_code, new_password) VALUES (%s, %s, %s)"

            # Insert verification code
            cursor.execute(delete_verification_query, (email,))
            connection.commit()

            cursor.execute(
                insert_verification_query,
                (email, verification_code, hashed_new_password),
            )
            connection.commit()

        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Something went wrong: {}".format(err)}), 500
        finally:
            if cursor is not None:
                cursor.close()
        EmailHandler.sendPasswordChangeVerificationEmail(
            email, verification_code, username
        )
        return jsonify({"email": email, "verification_code": verification_code}), 200

    @classmethod
    def confirmChangePassword(cls, request):
        data = request.json
        email = data.get("email")
        verification_code = data.get("verification_code")

        if not email or not verification_code:
            return jsonify({"error": "Missing email, verification code"}), 400
        cursor = None

        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception(
                    "UsersHandler :: confirmChangePassword :: connection is None"
                )
            cursor = connection.cursor()

            # Query to check if the email exists in the password_change table
            email_query = "SELECT * FROM password_change WHERE email = %s"
            cursor.execute(email_query, (email,))
            email_row = cursor.fetchone()

            if not email_row:
                return jsonify({"error": "Invalid email"}), 400

            # Query to check if the verification_code matches
            code_query = "SELECT * FROM password_change WHERE email = %s AND verification_code = %s"
            cursor.execute(code_query, (email, verification_code))
            code_row = cursor.fetchone()

            if not code_row:
                return jsonify({"error": "Invalid verification code"}), 400

            # Query to check if the code is not older than 3 minutes
            verification_query = """
            SELECT * FROM password_change
            WHERE email = %s AND verification_code = %s
            AND created_at >= NOW() - INTERVAL 3 MINUTE
            """
            cursor.execute(verification_query, (email, verification_code))
            verification_row = cursor.fetchone()

            if not verification_row:
                return jsonify({"error": "Verification code has expired"}), 400

            # Update the user's password in the users table
            new_password = verification_row[4]
            update_password_query = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(update_password_query, (new_password, email))
            connection.commit()

            # Retrieve the username from the users table
            username_query = "SELECT username FROM users WHERE email = %s"
            cursor.execute(username_query, (email,))
            user_record = cursor.fetchone()

            if user_record:
                username = user_record[0]
                return (
                    jsonify(
                        {
                            "status": "OK",
                            "message": "Successfully changed password!",
                            "username": username,
                            "email": email,
                        }
                    ),
                    200,
                )
            else:
                return jsonify({"error": "User not found"}), 404

        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Something went wrong: {}".format(err)}), 500
        finally:
            if cursor is not None:
                cursor.close()

    @classmethod
    def forgotPassword(cls, request):
        data = request.json
        username = data.get("username")
        new_password = data.get("new_password")
        hashed_new_password = generate_password_hash(new_password)
        email = data.get("email")

        if not username and not email or not new_password:
            return jsonify({"error": "Missing username or email or password"}), 400
        cursor = None

        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("UsersHandler :: forgotPassword :: connection is None")
            cursor = connection.cursor()

            # Fetch the user's current password and email
            if username:
                user_query = "SELECT password, email FROM users WHERE username = %s"
                cursor.execute(user_query, (username,))
            elif email:
                user_query = "SELECT password FROM users WHERE email = %s"
                cursor.execute(user_query, (email,))
            user_record = cursor.fetchone()

            if user_record:
                current_password = user_record[0]
                # Compare the current password with the new password
                if check_password_hash(current_password, new_password):
                    return (
                        jsonify(
                            {
                                "error": "New password cannot be the same as the current password"
                            }
                        ),
                        400,
                    )
                if username and not email:
                    email = user_record[1]
            else:
                return jsonify({"error": "User not found"}), 404

            verification_code = "{:06d}".format(random.randint(100000, 999999))
            delete_verification_query = "DELETE FROM password_forgot WHERE email = %s"
            insert_verification_query = "INSERT INTO password_forgot (email, verification_code, new_password) VALUES (%s, %s, %s)"

            # Insert verification code
            cursor.execute(delete_verification_query, (email,))
            connection.commit()

            cursor.execute(
                insert_verification_query,
                (email, verification_code, hashed_new_password),
            )
            connection.commit()

        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Something went wrong: {}".format(err)}), 500
        finally:
            if cursor is not None:
                cursor.close()
        EmailHandler.sendForgotPasswordEmail(email, verification_code, username)
        return jsonify({"email": email, "verification_code": verification_code}), 200

    @classmethod
    def confirmForgotPassword(cls, request):
        data = request.json
        email = data.get("email")
        verification_code = data.get("verification_code")

        headers = request.headers
        # auth = headers.get("auth_token")  # Use .get to avoid KeyError if "auth_token" is missing
        # if not auth or auth != auth_token:
        #     return jsonify({"error": "Invalid auth token"}), 403  # 403 Forbidden for auth issues

        if not email or not verification_code:
            return jsonify({"error": "Missing email, verification code"}), 400
        cursor = None

        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception(
                    "UsersHandler :: confirmForgotPassword :: connection is None"
                )
            cursor = connection.cursor()

            # Query to check if the email and verification_code match and the code is not older than 3 minutes
            verification_query = """
            SELECT * FROM password_forgot
            WHERE email = %s AND verification_code = %s
            AND created_at >= NOW() - INTERVAL 3 MINUTE
            """
            cursor.execute(verification_query, (email, verification_code))
            row = cursor.fetchone()
            if row:
                # Update the user's password in the users table
                new_password = row[4]
                # hashed_password = generate_password_hash(new_password)

                update_password_query = (
                    "UPDATE users SET password = %s WHERE email = %s"
                )
                cursor.execute(update_password_query, (new_password, email))
                connection.commit()

                # Retrieve the username from the users table
                username_query = "SELECT username FROM users WHERE email = %s"
                cursor.execute(username_query, (email,))
                user_record = cursor.fetchone()
                if user_record:
                    username = user_record[0]
                    return (
                        jsonify(
                            {
                                "status": "OK",
                                "message": "Successfully changed password!",
                                "username": username,
                                "email": email,
                            }
                        ),
                        200,
                    )
                else:
                    return jsonify({"error": "User not found"}), 404
            else:
                return (
                    jsonify(
                        {
                            "error": "Invalid email or verification code, or code has expired"
                        }
                    ),
                    400,
                )
        except mariadb.Error as err:
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Database error"}), 500
        finally:
            if cursor:
                cursor.close()

    @classmethod
    def weblogin(cls, request):
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400
        cursor = None

        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("UsersHandler :: weblogin :: connection is None")
            cursor = connection.cursor()

            # Fetch the user by email
            user_query = "SELECT user_id, email, password FROM users WHERE email = %s"
            cursor.execute(user_query, (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user[2], password):
                return UsersHandler.buildUserObject(user[0])
            else:
                return jsonify({"error": "Invalid email or password"}), 400
        except Exception as e:
            print(f"Something went wrong: {e}")
            return jsonify({"error": f"Something went wrong: {e}"}), 500
        finally:
            if cursor is not None:
                cursor.close()


    @classmethod
    def currentUserProfile(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 401

        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (
                JWT_ALGORITHM is None
            ):
                raise Exception("UsersHandler :: buildUserObject :: Env vars not found")
            # Decode the refresh token to get the user_id
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            token_type = payload.get("token_type")

            if not token_type or token_type != "refresh":
                return jsonify({"error": "Invalid refresh token"}), 401
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401

            return UsersHandler.buildUserObject(user_id,None,False)
        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401

    @classmethod
    def userOrders(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (
                JWT_ALGORITHM is None
            ):
                raise Exception("UsersHandler :: buildUserObject :: Env vars not found")
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid refresh token"}), 401

        limit = request.args.get('limit', type=int)
        page = request.args.get('page', type=int)

        if not limit: 
            limit = 4
        if not page: 
            page = 1

        connection = AppHandler.connection
        if connection is None:
            raise Exception("UsersHandler :: userOrders :: connection is None")
        cursor = connection.cursor()

        # Select active orders
        select_active_orders_query = """
        SELECT order_id
        FROM Orders
        WHERE user = %s
        ORDER BY createdDate DESC
        """
        if limit is not None and page is not None:
            select_active_orders_query += "LIMIT %s OFFSET %s"
            cursor.execute(select_active_orders_query, (user_id, limit, (page-1)*limit))
        else:
            cursor.execute(select_active_orders_query, (user_id,))
        active_order_ids = [order[0] for order in cursor.fetchall()]

        # Count active orders
        count_active_orders_query = """
        SELECT COUNT(*)
        FROM Orders
        WHERE user = %s
        """
        cursor.execute(count_active_orders_query, (user_id,))
        active_order_count = cursor.fetchone()[0]

        # Count archived orders
        count_archived_orders_query = """
        SELECT COUNT(*)
        FROM Archived_Orders
        WHERE user = %s
        """
        cursor.execute(count_archived_orders_query, (user_id,))
        archived_order_count = cursor.fetchone()[0]

        # Select archived orders
        select_archived_orders_query = """
        SELECT order_id
        FROM Archived_Orders
        WHERE user = %s
        ORDER BY createdDate DESC
        """
        if limit is not None and page is not None:
            select_archived_orders_query += "LIMIT %s OFFSET %s"
            cursor.execute(select_archived_orders_query, (user_id, limit, (page-1)*limit))
        else:
            cursor.execute(select_archived_orders_query, (user_id,))
        archived_order_ids = [order[0] for order in cursor.fetchall()]

        if cursor: 
            cursor.close()

        active_orders = [OrdersHandler.buildOrderObject(order_id) for order_id in active_order_ids]
        archived_orders = [OrdersHandler.buildArchivedOrder(order_id) for order_id in archived_order_ids]
        orders = active_orders + archived_orders

        total_count = archived_order_count + active_order_count
        page_count = total_count // limit if limit else 1

        return jsonify({
            "total_count": total_count,
            "page_count": page_count,
            "data": orders
        })

    @classmethod
    def userActiveOrder(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (
                JWT_ALGORITHM is None
            ):
                raise Exception("UsersHandler :: userActiveOrder :: Env vars not found")
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid refresh token"}), 401

        connection = AppHandler.connection
        if connection is None:
            raise Exception("UsersHandler :: userActiveOrder :: connection is None")
        cursor = connection.cursor()

        select_orders_query = """
        SELECT order_id
        FROM Orders
        WHERE user = %s AND OrderStatus = 100
        ORDER BY createdDate DESC
        LIMIT 1
        """
        cursor.execute(select_orders_query, (user_id,))

        order_id = cursor.fetchone()
        if not order_id:
            return jsonify({"error": "No orders found for this user"}), 404

        if cursor: 
            cursor.close()

        order = OrdersHandler.buildOrderObject(order_id[0])
        return jsonify(order)

    @classmethod
    def userOrder(cls, request, order_id):
        refresh_token = request.cookies.get("refresh_token")
        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (
                JWT_ALGORITHM is None
            ):
                raise Exception("UsersHandler :: userActiveOrder :: Env vars not found") 
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid refresh token"}), 401

        connection = AppHandler.connection
        if connection is None:
            raise Exception("UsersHandler :: userOrder :: connection is None")
        cursor = connection.cursor()

        select_order_query = """
        SELECT order_id
        FROM Orders
        WHERE user = %s AND order_id = %s
        """
        cursor.execute(select_order_query, (user_id, order_id))
        order = cursor.fetchone()

        if order is None:
            select_archived_order_query = """
            SELECT order_id
            FROM Archived_Orders
            WHERE user = %s AND order_id = %s
            """
            cursor.execute(select_archived_order_query, (user_id, order_id))
            order = cursor.fetchone()
            if order is None:
                return jsonify({"error": "Order not found"}), 404
            else:
                order_object = OrdersHandler.buildArchivedOrder(order[0])
        else:
            order_object = OrdersHandler.buildOrderObject(order[0])

        if cursor: 
            cursor.close()

        if order_object is None:
            return jsonify({"error": "Order not found"}), 404

        
        return jsonify(order_object)
