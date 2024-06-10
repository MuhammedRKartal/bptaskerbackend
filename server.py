#source ~/wt_backend/.venv/bin/activate
#~/wt_backend/.venv/bin/python3 ~/wt_backend/server.py
#sudo systemctl status backend.service
#sudo systemctl restart snap.rocketchat-server.rocketchat-server

#rocket chat administrator/M)8PcDXh,yI3}.I

#https://wowtasker.io/static/TaskerControlCenter.zip
#https://wowtasker.io/static/navserver.zip
# Standard library imports
import binascii
import hashlib
import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta
import traceback
from PIL import Image

# Related third-party imports
import qrcode

import jwt
import mariadb
import requests
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, abort, g, jsonify, request,make_response
from flask_limiter import Limiter
from werkzeug.exceptions import BadRequest
import redis

from flask_limiter.util import get_remote_address
def create_rocketchat_user(username, email, password):
    url = "https://chat.wowtasker.io/api/v1/users.create"
    headers = {
        "X-Auth-Token": "iL80dyJDmBpBuOZpbTs8WdwGgMTLCxO8WCQ00ekPYFG",
        "X-User-Id": "BN5q3LFaeqJeBFni7",
        "Content-type": "application/json",
    }
    data = {
        "username": username,
        "email": email,
        "password": password,
        "name": username
    }
    response = requests.post(url, json=data, headers=headers)
    return response.json()

# user_info = create_rocketchat_user("newuser", "newuser@example.com", "securepassword123")

btcpay_url = 'https://btcpay705908.lndyn.com/api/v1'
store_id = 'GueiqsA78ESY1KiJkHaVzvSdQakdD8spXxD1XVJ1rSyF'
invoice_id = 'Cvkh3M2rFFKcWqvDw3asEV'
api_key = '80036276bb160ceee8f297bc7f450ff1012438b4'

JWT_SECRET = 'I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 300  # 5 minutes expiration time
ACCESS_TOKEN_EXPIRES_MINUTES = 15
REFRESH_TOKEN_EXPIRES_DAYS = 7
auth_token = "I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz"

invoice_status_lookup = {
    "New": {"code": 100, "text": "Order waiting"},
    "Processing": {"code": 200, "text": "Payment waiting"},
    "Settled": {"code": 400, "text": "Completed"},
    "Expired": {"code": 500, "text": "Expired"},
    "Invalid": {"code": 300, "text": "Confirmation waiting"},
}

invoice_status_code_lookup = {
    100: "Order waiting",
    200: "Payment waiting",
    300: "Confirmation waiting",
    400: "Completed",
    500: "Expired"
}

CURRENCY_SYMBOLS = {
    "USD": "$",
    "EUR": "€",
    "JPY": "¥",
    "GBP": "£",
    "AUD": "$",
    "CAD": "$",
    "CHF": "CHF",
    "CNY": "¥",
    "SEK": "kr",
    "NZD": "$",
    # Add more currencies and their symbols here
}
def create_qr_code(data, invoice_id):
    # Define the directory where the QR code images will be saved
    directory = "static/qrcodes"
    
    # Check if the directory exists, and create it if it does not
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Setup QR code generation
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=1,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Generate QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Define the file path for saving the QR code image
    file_path = os.path.join(directory, f"{invoice_id}.png")
    
    # Save the QR image as a file
    img.save(file_path)
    print(f"QR Code saved to {file_path}")


def get_db_connection():
    connection = None
    try:
        config = {
  'user': 'admin',
  'password': 'hwH}FjY48Rx?*TRzk0x`>oL=~na@,e',
  'host': '127.0.0.1',
  'database': 'tasker_login'
}

        connection = mariadb.connect(**config)
    except Error as e:
        print(f"The error '{e}' occurred")
    return connection




# ##email shit
# # Define to/from
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr



def sendemail(email,subject,body):

    sender = 'noreply@wowtasker.io'
    sender_title = "WoWTasker"
    recipient = email

    # Create message
    msg = MIMEText(body, 'html', 'utf-8')
    msg['Subject'] =  Header(subject, 'utf-8')
    msg['From'] = formataddr((str(Header(sender_title, 'utf-8')), sender))
    msg['To'] = recipient

    # Create server object with SSL option
    # Change below smtp.zoho.com, corresponds to your location in the world. 
    # For instance smtp.zoho.eu if you are in Europe or smtp.zoho.in if you are in India.
    server = smtplib.SMTP_SSL('smtp.zoho.com', 465)

    # Perform operations via server
    server.login('jimkramer3779@gmail.com', 'Bogodin1!')
    server.sendmail(sender, [recipient], msg.as_string())
    server.quit()
EMAIL_STYLE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="background-color: #15171e; font-family: Arial, sans-serif; margin: 0; padding: 0; color: #ffffff;">
<table bgcolor="#15171e" style="background-color:#15171e;background-image:linear-gradient(#15171e,#15171e); width: 100%; min-width: 100%; border-spacing: 0; border-collapse: collapse; margin: 0 auto; word-wrap: break-word; word-break: break-word;">
<tbody>
<tr>
<td bgcolor="#15171e" style="background-color:#15171e;background-image:linear-gradient(#15171e,#15171e); padding: 20px;">
<table width="600" border="0" cellpadding="0" cellspacing="0" align="center" valign="top" bgcolor="#1a1c23" style="width:600px;min-width:600px;border-spacing:0;border-collapse:collapse;margin:0 auto;word-wrap:break-word;word-break:break-word;background-color:#1a1c23;background-image:linear-gradient(#1a1c23,#1a1c23);">
<tbody>
<tr>
<td style="padding: 20px; background-color: #1a1c23; border: 1px solid #2e3036; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.2);">
"""

EMAIL_DISCLAIMER = """
<!-- Disclaimer -->
<div style="margin-top: 20px; font-size: 12px; text-align: center; color: #666666;">
    <p>Disclaimer: The WowTasker team is committed to your privacy and security. Please be aware that we will never ask for your personal information, including your username, email, or password, outside of our official ticketing system. If you receive any requests for such information via email, social media, or any other channels not directly linked to our ticketing system, do not respond. These are not authorized by WowTasker and could be phishing attempts. For your safety, always ensure you are communicating through our secure, official channels. If you have any doubts or concerns, please contact us directly through our official website support system.</p>
</div>
<div style="margin-top: 20px; font-size: 12px; text-align: center; color: #666666;">
    &copy; 2024 WoWTasker.io. All rights reserved.
</div>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
</tbody>
</table>
</body>
</html>
"""

def send_verification_email(email, code, username):
    confirmation_email = f"""
{EMAIL_STYLE}
<title>Verification Code</title>
<div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
    <h2>Verify Your Email Address</h2>
</div>
<div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
    <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
    <p style="font-size: 16px; color: #ffffff;">Thank you for registering with WoWTasker.io! To complete your registration, please enter the following verification code on our website:</p>
    <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
    <br>
    <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
    <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
    <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
</div>
<!-- Image Insertion -->
<div style="text-align: center; margin: 20px 0;">
    <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
</div>
{EMAIL_DISCLAIMER}
"""
    sendemail(email, "Your WoWTasker.io Registration Verification Code", confirmation_email)
def send_password_change_verification_email(email, code, username):
    confirmation_email = f"""
{EMAIL_STYLE}
<title>Password Change Verification Code</title>
<div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
    <h2>Verify Your Password Change Request</h2>
</div>
<div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
    <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
    <p style="font-size: 16px; color: #ffffff;">We received a request to change your password on WoWTasker.io! To confirm this request, please enter the following verification code on our website:</p>
    <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
    <br>
    <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
    <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
    <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
</div>
<!-- Image Insertion -->
<div style="text-align: center; margin: 20px 0;">
    <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
</div>
{EMAIL_DISCLAIMER}
"""
    sendemail(email, "Your WoWTasker.io Password Change Verification Code", confirmation_email)
def send_forgot_password_email(email, code, username):
    forgot_password_email = f"""
{EMAIL_STYLE}
<title>Forgot Password Verification Code</title>
<div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
    <h2>Verify Your Forgot Password Request</h2>
</div>
<div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
    <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
    <p style="font-size: 16px; color: #ffffff;">We received a request to reset your password on WoWTasker.io! To confirm this request, please enter the following verification code on our website:</p>
    <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
    <br>
    <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
    <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
    <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
</div>
<!-- Image Insertion -->
<div style="text-align: center; margin: 20px 0;">
    <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
</div>
{EMAIL_DISCLAIMER}
"""
    sendemail(email, "Your WoWTasker.io Forgot Password Verification Code", forgot_password_email)
def send_delete_user_verification_email(email, code, username):
    confirmation_email = f"""
{EMAIL_STYLE}
<title>User Deletion Verification Code</title>
<div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
    <h2>Verify Your User Deletion Request</h2>
</div>
<div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
    <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
    <p style="font-size: 16px; color: #ffffff;">We received a request to delete your account on WoWTasker.io! To confirm this request, please enter the following verification code on our website:</p>
    <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
    <br>
    <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
    <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
    <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
</div>
<!-- Image Insertion -->
<div style="text-align: center; margin: 20px 0;">
    <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
</div>
{EMAIL_DISCLAIMER}
"""
    sendemail(email, "Your WoWTasker.io User Deletion Verification Code", confirmation_email)
def send_account_deleted_email(email, username):
    account_deleted_email = f"""
{EMAIL_STYLE}
<title>Account Deleted</title>
<div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
    <h2>Your Account Has Been Deleted</h2>
</div>
<div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
    <p style="font-size: 24px; font-weight: bold; color: #ffffff;">Hello {username},</p>
    <p style="font-size: 16px; color: #ffffff;">Your account has been deleted. You are lost, but not forgotten. If you wish to register again, we would love to have you back at any time.</p>
    <a href="http://wowtasker.io/register" style="font-size: 16px; display: inline-block; background-color: #4CAF50; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 20px 0;">Register Again</a>
    <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
</div>
<!-- Image Insertion -->
<div style="text-align: center; margin: 20px 0;">
    <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
</div>
{EMAIL_DISCLAIMER}
"""
    sendemail(email, "Your Account Has Been Deleted", account_deleted_email)
def send_payment_confirmation_email(email, username, product_name, invoice_id):
    confirmation_email = f"""
{EMAIL_STYLE}
<title>Payment Confirmation</title>
<div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
    <h2>Payment Confirmation</h2>
</div>
<div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
    <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
    <p style="font-size: 16px; color: #ffffff;">Thank you for your purchase!</p>
    <p style="font-size: 16px; color: #ffffff;">We have received your payment for {product_name}! Your invoice ID is {invoice_id}. You now have access to the <a href="http://wowtasker.io/downloads">Downloads Page</a></p>
    <p style="font-size: 16px; color: #ffffff;">Please have a look at our <a href="http://wowtasker.io/gettingstarted">Getting Started Guide</a></p>
    
    
    <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
</div>
<!-- Image Insertion -->
<div style="text-align: center; margin: 20px 0;">
    <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
</div>
{EMAIL_DISCLAIMER}
"""
    sendemail(email, "Your WoWTasker.io Payment Confirmation", confirmation_email)
app = Flask(__name__) 
limiter = Limiter(app=app, key_func=get_remote_address)
#queries unlocker licenses and returns licenses that are not in use for active sessions
#requres user_id
def get_available_unlocker_licenses(user_id):
    connection = get_db_connection()
    try:
        
        #clean up old sessions, then check for available licenses
        cleanup_old_sessions(connection)
    except Exception as e:
        print(f"Error: {e}")
        return []
        
    try:
        with connection.cursor(dictionary=True) as cursor:
            query = """
                SELECT ul.unlocker_license
                FROM unlocker_licenses ul
                LEFT JOIN unlocker_sessions us ON ul.unlocker_license = us.unlocker_license_id
                WHERE us.unlocker_license_id IS NULL AND ul.user_id = %s;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            # Extracting unlocker_license values into a list
            available_licenses = [row["unlocker_license"] for row in result]
            return available_licenses
    except Exception as e:
        print(f"Error: {e}")
        return []
def get_product_name(id):
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            query = """
                SELECT name
                FROM products
                WHERE pk = %s;
            """
            cursor.execute(query, (id,))
            result = cursor.fetchone()
            return result["name"]
    except Exception as e:
        print(f"Error: {e}")
        return None
def allocate_license(user_id, product, amount):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        # First, check if the user exists
        user_exists_query = "SELECT user_id, username, email FROM users WHERE user_id = %s;"
        cursor.execute(user_exists_query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return False, 0

        # If the user exists, proceed to allocate the unlocker licenses
        select_query = "SELECT unlocker_license FROM unused_unlocker_licenses LIMIT %s;"
        cursor.execute(select_query, (amount,))
        licenses = cursor.fetchall()
        if len(licenses) < amount:
            cursor.close()
            connection.close()
            sendemail("earshelh@gmail.com",'Licence allocation failure!',f'User {user_id} paid for {get_product_name(product)} but could not allocate the requested number of licenses. Allocated 0 out of {amount}.')
            return False, len(licenses)

        insert_query = "INSERT INTO unlocker_licenses (user_id, user_name, email, unlocker_license, enabled) VALUES (%s, %s, %s, %s, %s);"
        delete_query = "DELETE FROM unused_unlocker_licenses WHERE unlocker_license = %s;"
        try:
            for license in licenses:
                cursor.execute(insert_query, (user[0], user[1], user[2], license[0], 1))
                cursor.execute(delete_query, (license[0],))
            connection.commit()
            num_rows_affected = cursor.rowcount

            if num_rows_affected < amount:
                sendemail("earshelh@gmail.com",'Licence allocation failure!',f'User {user_id} paid for {product} but could not allocate the requested number of licenses. Allocated {num_rows_affected} out of {amount}.')
                raise mariadb.Error(f"Could not allocate the requested number of licenses. Allocated {num_rows_affected} out of {amount}.")

        except mariadb.IntegrityError:
            # This block catches an IntegrityError, which includes violations of UNIQUE constraints
            return False, num_rows_affected
        except mariadb.Error as err:
            # Handle other potential errors
            print("Error: ", err)
            return False, num_rows_affected
        finally:
            cursor.close()
            connection.close()
        sendemail("earshelh@gmail.com",'Order success!',f'User {user_id} paid for {product}. Allocated {num_rows_affected} out of {amount}.')
        return True, num_rows_affected
    else:
        return False, 0
def create_unlocker_session(unlocker_license,user_id):
    #create random number to add to the session table
    #and return it to the client via heartbeat
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        query = """
        INSERT INTO unlocker_sessions (session_id, unlocker_license_id, user_id, pid, last_heartbeat, created_at)
        VALUES (UUID(), %s, %s, 0, NOW(), NOW());
        """
        cursor.execute(query, (unlocker_license,user_id))
        connection.commit()
        response = {"status":"OK","unlocker_license_id":unlocker_license}
    except mariadb.Error as err:
        print(f"Error: {err}")
        response={"error":"Error!"}
    finally:
        cursor.close()
        connection.close()
    return response
def create_launcher_session(user_id):
    #create random number to add to the session table
    #and return it to the client via heartbeat
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        #     CREATE TABLE `launcher_sessions` (
    #   `session_id` varchar(64) PRIMARY KEY,
    #   `user_id` varchar(64),
    #   `last_heartbeat` timestamp,
    #   `created_at` timestamp
    # );
        query = """
        INSERT INTO launcher_sessions (session_id, user_id, last_heartbeat, created_at)
        VALUES (%s, %s, NOW(), NOW());
        """
        session_id = str(uuid.uuid4())
        cursor.execute(query, (session_id,user_id,))
        connection.commit()
        response = session_id
    except mariadb.Error as err:
        print(f"Error: {err}")
        response={"error":"Error!"}
    finally:
        cursor.close()
        connection.close()
    return response

def file_hash(filepath, hash_func='sha256'):
    """
    Generate a hash for a file.

    :param filepath: Path to the file to hash
    :param hash_func: Name of the hash function to use (e.g., 'sha256', 'md5')
    :return: The hexadecimal hash string of the file
    """
    # Create a hash object
    h = hashlib.new(hash_func)
    # Open the file in binary mode and update the hash object with chunks
    with open(filepath, 'rb') as file:
        while chunk := file.read(8192):
            h.update(chunk)
    # Return the hexadecimal digest of the hash
    return h.hexdigest()

def terminate_all_sessions(user_id):
    if not user_id:
        return
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        query = "DELETE FROM unlocker_sessions WHERE user_id = %s;"
        cursor.execute(query, (user_id,))
        connection.commit()
        response = {"status":"OK"}
    except mariadb.Error as err:
        print(f"Error: {err}")
        response={"error":"Error!"}
    finally:
        cursor.close()
        connection.close()
    return response


def cleanup_old_sessions(connection):
    with connection.cursor() as cursor:
        # Delete sessions older than 3 minutes
        # 1 minute should be plenty, as the bot will be
        # sending heartbeats every 10 seconds or so
        # this is a dance, deciding on how long to keep
        # unlocker keys going for. 3 minutes should
        # allow for time to transition between characters
        # and such
        # TODO implement PID tracking from the launcher,
        # so that if a pid is closed, the unlocker key is
        # automatically added back into the pool

        cleanup_query = """
        DELETE FROM unlocker_sessions
        WHERE last_heartbeat < NOW() - INTERVAL 1 MINUTE;
        """
        cursor.execute(cleanup_query)
        connection.commit()

#replaced with get ul session
#disabled temporarily, maybe permanently
# @app.route("/licenseinfo", methods=["GET"])
# def get_license_info():
#     userID = request.json.get('userID')
#     print(request.json)
#     if userID and userID in unlocker_keys:
#         resp = {"status": "OK","keys":unlocker_keys[userID]}
#         return jsonify(resp)
#     return jsonify({"status":"ERROR","message":"Couldn't fetch license keys for user."})




#add user to database
#requires: username, password,auth key
# adduser?username=exe&password=utiy&auth=I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz
#merdos 5a6fe760352a0397a672a6b1aae2dbf0401720204e49c9da 
#nasen bd3998f3747fb38d80a2c883faf86321c4832dc2ebb30dd9 
#insert into 'unlocker_license' 
@app.route("/web/adduser")
def addUser():
    
    username = request.args.get("username")
    password = request.args.get("password")
    auth = request.args.get("auth")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if not auth or (auth and auth != auth_token):
        return jsonify({"error": "Invalid auth token"}), 400
    
    #we won't store the plaintext password. hash it
    hashed_password = generate_password_hash(password)
    
    #token to be used for session purposes
    token = binascii.hexlify(os.urandom(24)).decode()
    

    connection = get_db_connection()
    
    if connection:
        cursor = connection.cursor()
        query = "INSERT INTO users (user_id, username, password) VALUES (%s, %s, %s);"
        try:
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
            connection.close()
        return jsonify({"message": "User added successfully", "token": token}), 200
    else:
        return jsonify({"error": "Failed to connect to the database"}), 500





##begin /web/ api endpoints
def create_access_token(data, expires_delta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire,"token_type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(data, expires_delta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire,"token_type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt
def refresh_tokens_if_needed():
    refresh_token = request.cookies.get('refresh_token')
    response = make_response()  # Prepare an empty response

    if refresh_token:
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": True})
            if payload['token_type'] != 'refresh':
                # The token is not a refresh token
                return response  # Return the original response without modification

            user_id = payload['user_id']
            # Generate a new access token
            new_access_token = create_access_token(data={"user_id": user_id}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES))
            # Optionally, generate a new refresh token here as well
            new_refresh_token = create_refresh_token(data={"user_id": user_id}, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS))
            # Set the new access token in the response cookies
            response.set_cookie("refresh_token", new_refresh_token, secure=True,httponly=True, samesite='Strict',max_age=60*60*24)
            # Optionally, set the new refresh token in the response cookies

            return response  # Return the response with the new tokens set
        except jwt.PyJWTError:
            # Refresh token is invalid or expired
            pass  # Do nothing, just return the original response

    return response  # Return the original response if no refresh token or if any error occurs

def check_access_and_refresh_tokens():
    access_token = request.cookies.get('access_token')
    refresh_token = request.cookies.get('refresh_token')

    if access_token:
        try:
            payload = jwt.decode(access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            # Access token is valid, return user_id (or other user details) from payload
            return {'user_id': payload['user_id']}, None
        except jwt.ExpiredSignatureError:
            # Access token is expired; attempt to use the refresh token
            pass
        except jwt.PyJWTError:
            # Access token is invalid
            return None, jsonify({"error": "Invalid access token"}), 401

    if refresh_token:
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": True})
            if payload['token_type'] != 'refresh':
                return None, jsonify({"error": "Invalid refresh token"}), 401
            # Refresh token is valid; generate a new access token
            user_id = payload['user_id']
            new_access_token = create_access_token(data={"user_id": user_id}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES))
            # Optionally, generate a new refresh token here as well

            # Set the new access token in the response
            resp = make_response()
            resp.set_cookie("access_token", new_access_token, httponly=True, samesite='Strict')
            # Optionally, set the new refresh token in the response

            return {'user_id': user_id}, resp
        except jwt.PyJWTError:
            # Refresh token is invalid
            return None, jsonify({"error": "Invalid refresh token"}), 401

    # No valid access or refresh token
    return None, jsonify({"error": "Authentication required"}), 401
def build_user_object(user_id, additional_data=None, refresh=True):
    # Fetch user details from the database
    connection = get_db_connection()
    cursor = connection.cursor()
    user_query = """
    SELECT user_id, username, email, verified, date_joined, email_allowed, eula_accepted
    FROM users WHERE user_id = %s
    """
    cursor.execute(user_query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id, username, email, verified, date_joined, email_allowed, eula_accepted = user

    # Create response with the user information
    user_info = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "verified": bool(verified),
        "date_joined": date_joined.strftime('%Y-%m-%d %H:%M:%S'),
        "email_allowed": bool(email_allowed),
        "eula_accepted": bool(eula_accepted)
    }

    # Merge the user_info and the additional_data
    if additional_data is not None:
        user_info = {**user_info, **additional_data}

    response = jsonify(user_info)

    if refresh:
        # Generate a new access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
        # new_access_token = create_access_token(data={"user_id": user_id}, expires_delta=access_token_expires)

        # Optionally, generate a new refresh token
        refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS)
        new_refresh_token = create_refresh_token(data={"user_id": user_id}, expires_delta=refresh_token_expires)
# 
        # response.headers['Authorization'] = 'Bearer ' + new_access_token
        # Set the new access token in an HTTP-only cookie
        # response.set_cookie("access_token", new_access_token, httponly=True, samesite='Strict')
        # Optionally, set the new refresh token in an HTTP-only cookie
        response.set_cookie("refresh_token", new_refresh_token, secure = True, httponly=True, samesite='Strict',max_age=60*60*24)

    return response
# ##example
# @app.route('/protected_endpoint', methods=['GET'])
# def protected_endpoint():
#     user, error_response = check_access_and_refresh_tokens()
#     if error_response:
#         return error_response

#     # At this point, user is authenticated, and you have their details in `user`
#     # Proceed with your endpoint logic
#     return jsonify({"message": "Access granted", "user_id": user['user_id']})
banned_username_words = ["admin", "administrator", "root", "superuser", "moderator", "mod", "staff", "support", "help", "contact", "info", "webmaster", "abuse", "postmaster", "hostmaster", "noc", "security", "sysadmin", "system", "tech", "web", "www", "ftp", "http", "https", "smtp", "pop3", "imap", "mail", "administator", "administrator","tasker"]

#curl -X POST https://wowtasker.io/web/register -H "Content-Type: application/json" -H "auth_token:I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d '{"email": "jimkramer3779@gmail.com","username":"earshy","password":"test"}'
@app.route("/web/user/allocate-license", methods=["POST"])
def allocate_license_endpoint():
    headers = request.headers
    auth = headers.get("auth")
    if not auth or (auth and auth != auth_token):
        return jsonify({"error": "Invalid auth token"}), 403

    data = request.json
    user_id = data.get("user_id")
    quantity = data.get("quantity")
    if not user_id or not quantity:
        return jsonify({"error": "Missing user_id or quantity"}), 400

    result = allocate_license(user_id, 1,quantity)
    if "error" in result:
        return jsonify(result), 400
    else:
        return jsonify(result), 200
@app.route("/web/user/register", methods=["POST"])
@limiter.limit("2/minute")  # Adjust the limit as needed
def register():
    print('Register endpoint hit')
    data = request.json
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    
    
    headers = request.headers
    print('Headers:', headers)
    # if not headers["auth_token"]:
    #     return jsonify({"error": "Invalid auth token"}), 403
    # auth = headers["auth_token"]

    if not username or not password or not email:
        print('Missing username, password, or email')
        return jsonify({"error": "Missing username, password, or email"}), 400
    # if not auth or auth != auth_token:
    #     print('Invalid auth token')
    #     return jsonify({"error": "Invalid auth token"}), 403
    disallowed_words = [word for word in banned_username_words if word in username.lower()]
    if disallowed_words:
        print('Username contains reserved words:', disallowed_words)
        return jsonify({"error": "Username contains reserved words", "disallowed_words": disallowed_words}), 400
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check if a user with the provided email already exists
        check_user_query = "SELECT email FROM users WHERE email = %s"
        cursor.execute(check_user_query, (email,))
        user = cursor.fetchone()

        if user:
            return jsonify({"error": "User with this email already exists"}), 400

        # ... (rest of your code)

    except mariadb.Error as err:
        print("Something went wrong:", err)
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        connection.close()
    hashed_password = generate_password_hash(password)
    token = binascii.hexlify(os.urandom(24)).decode()
    verification_code = "{:06d}".format(random.randint(100000, 999999))
    delete_verification_query = "DELETE FROM user_registration WHERE email = %s"
    insert_verification_query = "INSERT INTO user_registration (email, verification_code,password) VALUES (%s, %s,%s)"
    
    print('Prepared queries and data')
    
    try:
        print('Trying to establish database connection')
        connection = get_db_connection()
        cursor = connection.cursor()
        print('Database connection established')

        user_insert_query = "INSERT INTO users (user_id, email, username, password) VALUES (%s, %s, %s, %s);"
        print('Executing user insert query')
        cursor.execute(user_insert_query, (token, email, username, hashed_password))
        connection.commit()
        print('User insert query executed')

        print('Executing delete verification query')
        cursor.execute(delete_verification_query, (email,))
        connection.commit()
        print('Delete verification query executed')

        print('Executing insert verification query')
        cursor.execute(insert_verification_query, (email, verification_code,password))
        connection.commit()
        print('Insert verification query executed')

    except mariadb.IntegrityError as err:
        print('Integrity error:', err)
        check_user_query = "SELECT verified FROM users WHERE email = %s"
        cursor.execute(check_user_query, (email,))
        user = cursor.fetchone()
        if user and user[0] == 0:  # User exists but not verified
            print('User exists but not verified')
            cursor.execute(delete_verification_query, (email,))
            cursor.execute(insert_verification_query, (email, verification_code,password))
            connection.commit()
            send_verification_email(email,verification_code,username)
            return jsonify({"email": email}), 200
            # return jsonify({"email": email, "verification_code": verification_code}), 200
        else:
            print('User already exists')
            return jsonify({"error": "User already exists"}), 400
    except mariadb.Error as err:
        print("Something went wrong:", err)
        return jsonify({"error": "Database error"}), 500
    finally:
        print('Closing database connection')
        cursor.close()
        connection.close()
        print('Database connection closed')
    send_verification_email(email,verification_code,username)
    return jsonify({"email": email, "username": username}), 200
#curl -X POST https://wowtasker.io/web/confirmregistration -H "Content-Type: application/json" -H "auth_token:I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d '{"email": "earshelh@gmail.com","verification_code":513318}'
@app.route("/web/user/confirm-registration", methods=["POST"])
def confirm_registration():
    data = request.json
    email = data.get("email")
    verification_code = data.get("verification_code")

    if not email or not verification_code:
        return jsonify({"error": "Missing email or verification code"}), 400
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()

            # Query to check if the email and verification_code match, regardless of the code's age
            verification_query = """
            SELECT password FROM user_registration
            WHERE email = %s AND verification_code = %s
            """
            cursor.execute(verification_query, (email, verification_code))
            record = cursor.fetchone()

            if not record or record[0] != verification_code:
                return jsonify({"error": "Your verification code is incorrect."}), 400
            print(verification_code)
            print("D"+record[0])
            # Query to check if the verification_code is not older than 3 minutes
            expiration_query = """
            SELECT password FROM user_registration
            WHERE email = %s AND verification_code = %s
            AND created_at >= NOW() - INTERVAL 3 MINUTE
            """
            cursor.execute(expiration_query, (email, verification_code))
            record = cursor.fetchone()

            if not record:
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

                return build_user_object(user_id)
            else:
                return jsonify({"error": "User not found"}), 404
        else:
            return jsonify({"error": "Database connection failed"}), 500
    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
        return jsonify({"error": "Database error"}), 500
    finally:
        if cursor: cursor.close()
        if connection: connection.close()

    return jsonify({"error": "An unexpected error occurred"}), 500
#debian curl -X POST https://wowtasker.io/web/user/password/change -H "Content-Type: application/json" -H "auth_token:I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d '{"email": "earshelh@gmail.com","username":"eazrshsy2s","current_password":"Bogodin2!","new_password":"Bogodin1!"}'
#windows curl -X POST https://wowtasker.io/web/user/password/change -H "Content-Type: application/json" -H "auth_token: I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d "{\"email\": \"earshelh@gmail.com\",\"username\":\"eazrshsy2s\"}"
@app.route("/web/user/password/change", methods=["POST"])
def change_password():
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

    try:
        connection = get_db_connection()
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
                return jsonify({"error": "New password cannot be the same as the current password"}), 400
            elif not check_password_hash(current_password,current_password_from_json ):
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

        cursor.execute(insert_verification_query, (email, verification_code, hashed_new_password))
        connection.commit()

    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
        return jsonify({"error": "Something went wrong: {}".format(err)}), 500
    finally:
        cursor.close()
        connection.close()
    send_password_change_verification_email(email, verification_code, username)
    return jsonify({"email": email, "verification_code": verification_code}), 200
@app.route("/web/user/password/confirm-change", methods=["POST"])
def confirm_change_password():
    data = request.json
    email = data.get("email")
    verification_code = data.get("verification_code")

    if not email or not verification_code:
        return jsonify({"error": "Missing email, verification code"}), 400

    try:
        connection = get_db_connection()
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
            return jsonify({"status":"OK","message":"Successfully changed password!","username": username, "email": email}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
        return jsonify({"error": "Something went wrong: {}".format(err)}), 500
    finally:
        cursor.close()
        connection.close()
@app.route("/web/user/password/forgot", methods=["POST"])
def forgot_password():
    data = request.json
    username = data.get("username")
    new_password = data.get("new_password")
    hashed_new_password = generate_password_hash(new_password)
    email = data.get("email")

    if not username and not email or not new_password:
        return jsonify({"error": "Missing username or email or password"}), 400

    try:
        connection = get_db_connection()
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
                return jsonify({"error": "New password cannot be the same as the current password"}), 400
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

        cursor.execute(insert_verification_query, (email, verification_code, hashed_new_password))
        connection.commit()

    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
        return jsonify({"error": "Something went wrong: {}".format(err)}), 500
    finally:
        cursor.close()
        connection.close()
    send_forgot_password_email(email, verification_code, username)
    return jsonify({"email": email, "verification_code": verification_code}), 200
@app.route("/web/user/password/confirm-forgot", methods=["POST"])
def confirm_forgot_password():
    data = request.json
    email = data.get("email")
    verification_code = data.get("verification_code")
    
    
    headers = request.headers
    # auth = headers.get("auth_token")  # Use .get to avoid KeyError if "auth_token" is missing
    # if not auth or auth != auth_token:
    #     return jsonify({"error": "Invalid auth token"}), 403  # 403 Forbidden for auth issues

    if not email or not verification_code:
        return jsonify({"error": "Missing email, verification code"}), 400

    try:
        connection = get_db_connection()
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
            new_password=row[4]
            # hashed_password = generate_password_hash(new_password)
            
            update_password_query = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(update_password_query, (new_password, email))
            connection.commit()

            # Retrieve the username from the users table
            username_query = "SELECT username FROM users WHERE email = %s"
            cursor.execute(username_query, (email,))
            user_record = cursor.fetchone()
            if user_record:
                username = user_record[0]
                return jsonify({"status":"OK","message":"Successfully changed password!","username": username, "email": email}), 200
            else:
                return jsonify({"error": "User not found"}), 404
        else:
            return jsonify({"error": "Invalid email or verification code, or code has expired"}), 400
    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
        return jsonify({"error": "Database error"}), 500
    finally:
        if cursor: cursor.close()
        if connection: connection.close()

    return jsonify({"error": "An unexpected error occurred"}), 500
#debian curl -X POST https://wowtasker.io/web/deleteuser -H "Content-Type: application/json" -H "auth_token:I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d '{"email": "jimkramer3779@gmail.com"}'
#windows curl -X POST https://wowtasker.io/web/deleteuser -H "Content-Type: application/json" -H "auth_token: I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d "{\"email\": \"jimkramer3779@gmail.com\"}"
@app.route("/web/user/delete", methods=["POST"])
def delete_user():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    
    headers = request.headers
    auth = headers.get("auth_token")

    if not username and not email:
        return jsonify({"error": "Missing username or email"}), 400
    if not auth or auth != auth_token:
        return jsonify({"error": "Invalid auth token"}), 403

    try:
        connection = get_db_connection()
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

        verification_code = "{:06d}".format(random.randint(100000, 999999))
        delete_verification_query = "DELETE FROM delete_user WHERE email = %s"
        insert_verification_query = "INSERT INTO delete_user (email, verification_code) VALUES (%s, %s)"

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
        connection.close()
    send_delete_user_verification_email(email,verification_code,username)
    return jsonify({"email": email, "username": username, "verification_code": verification_code}), 200
#debian curl -X POST https://wowtasker.io/web/confirmdeleteuser -H "Content-Type: application/json" -H "auth_token:I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d '{"email": "jimkramer3779@gmail.com","verification_code":682929}'
#windows curl -X POST https://wowtasker.io/web/confirmdeleteuser -H "Content-Type: application/json" -H "auth_token: I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz" -d "{\"email\": \"jimkramer3779@gmail.com\",\"verification_code\":682929}"

@app.route("/web/user/confirm-delete", methods=["POST"])
def confirm_delete_user():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    verification_code = data.get("verification_code")
    
    headers = request.headers
    auth = headers.get("auth_token")  # Use .get to avoid KeyError if "auth_token" is missing
    if not auth or auth != auth_token:
        return jsonify({"error": "Invalid auth token"}), 403  # 403 Forbidden for auth issues

    if not email and not username or not verification_code:
        return jsonify({"error": "Missing email or username, or verification code"}), 400

    try:
        connection = get_db_connection()
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
            send_account_deleted_email(email,username)
            return jsonify({"status":"OK","message":"Successfully deleted user!","email":email}), 200
        else:
            return jsonify({"error": "Invalid email or verification code, or code has expired"}), 400
    except mariadb.Error as err:
        print("Something went wrong: {}".format(err))
        return jsonify({"error": "Database error"}), 500
    finally:
        if cursor: cursor.close()
        if connection: connection.close()

    return jsonify({"error": "An unexpected error occurred"}), 500
@app.route("/web/verify",methods=["POST"])
def verify():
    data = request.json
    email=data.get("email")
    username=data.get("username")
    verification_code=data.get("verification_code")
    headers = request.headers

    auth = headers["auth_token"]

    if not username or not verification_code or not email:
        return jsonify({"error": "Missing username or verification_code or email"}), 400
    if not auth or (auth and auth != auth_token):
        return jsonify({"error": "Invalid auth token"}), 400
    
    #we won't store the plaintext password. hash it
    hashed_password = generate_password_hash(password)
    
    #token to be used for session purposes
    token = binascii.hexlify(os.urandom(24)).decode()
    

    connection = get_db_connection()
    #check to see if there's an active code for this user

    if connection:
        cursor = connection.cursor()
        query = "INSERT INTO users (user_id, username,email, password) VALUES (%s, %s, %s,%s);"
        try:
            cursor.execute(query, (token, username,email, hashed_password))
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
            connection.close()
        return jsonify({"message": "User added successfully", "token": token}), 200
    else:
        return jsonify({"error": "Failed to connect to the database"}), 500
#curl -i -X POST http://wowtasker.io/web/login -H "Content-Type: application/json" -d '{"email": "test@example.com", "password": "testpassword"}'
@app.route("/web/user/login", methods=["POST"])
def weblogin():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Fetch the user by email
        user_query = "SELECT user_id, email, password FROM users WHERE email = %s"
        cursor.execute(user_query, (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            return build_user_object(user[0])
        else:
            return jsonify({"error": "Invalid email or password"}), 400
    except Exception as e:
        print(f"Something went wrong: {e}")
        return jsonify({"error": f"Something went wrong: {e}"}), 500
    finally:
        cursor.close()
        connection.close()

#curl -X POST http://wowtasker.io/web/refresh --cookie "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZTkxOTQyYmM2NzIyODA5Njg5ZWM2NTMzMWI1MmM3MmJlMzU1NWQ3YjE5OTFjZjBjIiwiZXhwIjoxNzEyNDIxOTU0LCJ0b2tlbl90eXBlIjoiYWNjZXNzIn0.qjMbAX1sOdjWn8sdt3r055KwSpUGoTZ600DcJM4fHmo"
@app.route("/web/refresh", methods=["POST"])
def refresh_token():
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 401

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")
        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}),401
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        # Generate a new access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
        new_access_token = create_access_token(data={"user_id": user_id}, expires_delta=access_token_expires)

        return jsonify({"access_token": new_access_token}), 200
    except jwt.PyJWTError:
        return jsonify({"error": "Invalid refresh token"}), 401

#debian curl -i -X GET http://wowtasker.io/web/currentuser --cookie "access_token=access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZTkxOTQyYmM2NzIyODA5Njg5ZWM2NTMzMWI1MmM3MmJlMzU1NWQ3YjE5OTFjZjBjIiwiZXhwIjoxNzEyNTA4MDYxLCJ0b2tlbl90eXBlIjoiYWNjZXNzIn0.Z91ukjt9MXAGLSTNfcQJOujrHb4ERoCww5ZN9NtnrqI;refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZTkxOTQyYmM2NzIyODA5Njg5ZWM2NTMzMWI1MmM3MmJlMzU1NWQ3YjE5OTFjZjBjIiwiZXhwIjoxNzEzMTExOTYxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.SN7dcfeucgE2Woj7vwTVW-stsPgSc_7_Jovkct-yOSA;"
#windows curl -i -X GET http://wowtasker.io/web/currentuser -H "Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZTkxOTQyYmM2NzIyODA5Njg5ZWM2NTMzMWI1MmM3MmJlMzU1NWQ3YjE5OTFjZjBjIiwiZXhwIjoxNzEyNTA4MDYxLCJ0b2tlbl90eXBlIjoiYWNjZXNzIn0.Z91ukjt9MXAGLSTNfcQJOujrHb4ERoCww5ZN9NtnrqI; refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZTkxOTQyYmM2NzIyODA5Njg5ZWM2NTMzMWI1MmM3MmJlMzU1NWQ3YjE5OTFjZjBjIiwiZXhwIjoxNzEzMTExOTYxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.SN7dcfeucgE2Woj7vwTVW-stsPgSc_7_Jovkct-yOSA"

@app.route("/web/currentuser", methods=["GET"])
def current_user():
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 401

    try:
        # Decode the refresh token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")

        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 401
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        return build_user_object(user_id)
    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
@app.route("/web/user/profile", methods=["GET"])
def current_user_profile():
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 401

    try:
        # Decode the refresh token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")

        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 401
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        return build_user_object(user_id,None,False)
    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
def build_product_details(row):
    if row is None or len(row) < 13:
        return {
            "pk": "",
            "name": "",
            "description": "",
            "short_description": "",
            "price": "",
            "retail_price": "",
            "currency_type": "",
            "currency_symbol": "",
            "in_stock": False,
            "attributes": {},
            "images": []
        }

    product_details = {
        "pk": row[0],
        "name": row[1],
        "description": row[2],
        "short_description": row[3],
        "price": str(row[4]),  # Convert Decimal to string
        "retail_price": str(row[5]),
        "currency_type": row[6],
        "currency_symbol": CURRENCY_SYMBOLS.get(row[6], ""),
        "in_stock": row[7],
        "attributes": {},
        "images": []
    }

    if row[8] is not None and row[9] is not None and row[10] is not None:  # If there's a feature
        product_details["attributes"][row[8]] = {"label": row[9], "value": row[10]}

    if len(row) > 11 and row[11] is not None:  # If there's an image URL
        product_details["images"].append({"url": row[11], "alt_text": row[12]})

    return product_details
@app.route("/web/products", methods=["GET"])
def get_all_products():
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Modified query to also fetch product features
        query = """
        SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
        FROM products p
        LEFT JOIN product_images pi ON p.pk = pi.product_id
        LEFT JOIN product_features pf ON p.pk = pf.product_id
        LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
        WHERE p.pk > 0;
        """
        cursor.execute(query)
        rows = cursor.fetchall()

        # Prepare the list of products for JSON response
        product_list = {}
        for row in rows:
            pk = row[0]
            
            if pk not in product_list:
                product_list[pk] = build_product_details(row)
            else:
                if row[8] and row[9]:  # If there's a feature
                    product_list[pk]["attributes"][row[8]] = {"label": row[9], "value": row[10]}
                if row[11]:  # If there's an additional image URL
                    product_list[pk]["images"].append({"url": row[11], "alt_text": row[12]})

        token_refresh_response = refresh_tokens_if_needed()

        # Merge product data into the token refresh response
        token_refresh_response.data = jsonify(list(product_list.values())).data

        return token_refresh_response

    except Exception as e:
        print(f"Something went wrong: {e}")
        return jsonify({"error": f"Something went wrong: {e}"}), 500
    finally:
        if cursor: cursor.close()
        if connection: connection.close()

@app.route("/web/products/<pk>", methods=["GET"])
def get_product_by_pk_or_name(pk):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Modified query to also fetch product features
        query = """
        SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
        FROM products p
        LEFT JOIN product_images pi ON p.pk = pi.product_id
        LEFT JOIN product_features pf ON p.pk = pf.product_id
        LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
        WHERE p.pk = %s OR p.name = %s
        """
        cursor.execute(query, (pk, pk))
        rows = cursor.fetchall()

        if not rows:
            return jsonify({"error": "Product not found"}), 404

        # Prepare the product details for JSON response
        product_details = build_product_details(rows[0])
        for row in rows[1:]:
            if row[8] and row[9]:  # If there's a feature
                product_details["attributes"][row[8]] = {"label": row[9], "value": row[10]}
            if row[11]:  # If there's an additional image URL
                product_details["images"].append({"url": row[11], "alt_text": row[12]})

        token_refresh_response = refresh_tokens_if_needed()

        # Merge product data into the token refresh response
        token_refresh_response.data = jsonify(product_details).data

        return token_refresh_response
    except Exception as e:
        print(f"Something went wrong: {e}")
        return jsonify({"error": f"Something went wrong: {e}"}), 500
    finally:
        if cursor: cursor.close()
        if connection: connection.close()
#basket api
def build_basket_object(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    # Get the basket details
    basket_query = """
    SELECT pk, total_amount, total_quantity
    FROM Basket
    WHERE user_id = %s
    """
    cursor.execute(basket_query, (user_id,))
    basket = cursor.fetchone()

    if not basket:
        return jsonify({"error": "Basket not found"}), 404

    # Get the basket items
    items_query = """
    SELECT BI.id, BI.stock, BI.quantity, BI.product, PI.image_url, BI.total_amount, BI.price, BI.currency_type
    FROM BasketItem BI
    LEFT JOIN (
        SELECT product_id, image_url
        FROM product_images
        GROUP BY product_id
    ) PI ON BI.product = PI.product_id
    WHERE BI.basket_id = %s
    """
    cursor.execute(items_query, (basket[0],))
    items = cursor.fetchall()

    # Build the basket object
    basket_object = {
        "pk": basket[0],
        "total_amount": str(basket[1]),
        "total_quantity": basket[2],
        "product_list": []
    }

    # Add the basket items to the product_list in the basket object
    for item in items:
        product_query = """
        SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
        FROM products p
        LEFT JOIN product_images pi ON p.pk = pi.product_id
        LEFT JOIN product_features pf ON p.pk = pf.product_id
        LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
        WHERE p.pk = %s
        """
        cursor.execute(product_query, (item[3],))
        product_rows = cursor.fetchall()

        product_details = build_product_details(product_rows[0])
        for row in product_rows[1:]:
            if row[8] is not None and row[9] is not None and row[10] is not None:  # If there's a feature
                product_details["attributes"][row[8]] = {"label": row[9], "value": row[10]}
            if row[11]:  # If there's an image URL
                product_details["images"].append({"url": row[11], "alt_text": row[12]})

        basket_object["product_list"].append({
            "item_id": item[0],
            "stock": item[1],
            "quantity": item[2],
            "product": product_details,
            "image": item[4],
            "total_amount": str(item[5]),
            "price": str(item[6]),
            "currency_type": item[7],
            "currency_symbol": CURRENCY_SYMBOLS.get(item[7], "")
        })


    cursor.close()
    connection.close()

    return basket_object
#debian curl -X POST -H "Content-Type: application/json" --cookie "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYzljMzk2MjRiNzU3ZTlkMzI5YzhkOTM1YjQwYTdmZTYwNTM3ZjFhNzAzNDk3MWEzIiwiZXhwIjoxNzEzMjI4MTcxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.D54pJKT7UuiWsjLlV-KN4c9aaNLGok8gd__wNZM2wRs" -d '{"productPk": 1, "quantity": 10}' http://wowtasker.io/web/basket/updateQuantity
#windows curl -X POST -H "Content-Type: application/json" --cookie "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYzljMzk2MjRiNzU3ZTlkMzI5YzhkOTM1YjQwYTdmZTYwNTM3ZjFhNzAzNDk3MWEzIiwiZXhwIjoxNzEzMjI4MTcxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.D54pJKT7UuiWsjLlV-KN4c9aaNLGok8gd__wNZM2wRs" -d "{""productPk"": 1, ""quantity"": 10}" http://wowtasker.io/web/basket/updateQuantity

@app.route("/web/basket/update-quantity", methods=["PUT"])
def update_quantity():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 401

    try:
        # Decode the refresh token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")

        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 401
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        # Get the productPk and quantity from the request body
        data = request.json
        product_pk = data.get("productPk")
        quantity = data.get("quantity")

        if not product_pk or quantity is None or quantity < 0:
            return jsonify({"error": "Missing productPk or invalid quantity"}), 400

        # Get a database connection
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check if a basket exists for the user
        basket_query = """
        SELECT pk FROM Basket WHERE user_id = %s
        """
        cursor.execute(basket_query, (user_id,))
        basket = cursor.fetchone()

        # If a basket doesn't exist, return an error
        if not basket:
            return jsonify({"error": "Basket not found"}), 404

        # Get the price, currency_type and stock of the product
        product_query = """
        SELECT price, currency_type, in_stock FROM products WHERE pk = %s
        """
        cursor.execute(product_query, (product_pk,))
        product = cursor.fetchone()

        if not product:
            return jsonify({"error": "Product not found"}), 404

        price, currency_type, stock = product
        price = float(price)
        quantity = int(quantity)
        stock = int(stock)

        if price == 0:
            return jsonify({"error": "Product price is zero"}), 400

        # Check if there is enough stock of the product
        if stock < quantity:
            return jsonify({"error": "Not enough stock","quantity_requested":quantity,"in_stock":stock}), 400

        # Check if a BasketItem exists with the given basket_id and product
        check_query = """
        SELECT id FROM BasketItem
        WHERE basket_id = %s
        AND product = %s
        """
        cursor.execute(check_query, (basket[0], product_pk))
        item = cursor.fetchone()

        # If no BasketItem exists, return an error
        if not item:
            return jsonify({"error": "Item not found in basket"},build_basket_object(user_id)), 404

        # If a BasketItem exists, update its quantity, total_amount, price, and currency_type
        if quantity == 0:
            delete_query = """
            DELETE FROM BasketItem
            WHERE id = %s
            """
            cursor.execute(delete_query, (item[0],))
        else:
            update_query = """
            UPDATE BasketItem
            SET quantity = %s, total_amount = %s, price = %s, currency_type = %s,stock = %s
            WHERE id = %s
            """
            cursor.execute(update_query, (quantity, price*quantity, price, currency_type, stock,item[0]))

        # Update the total_amount and total_quantity in the Basket table
        update_basket_query = """
        UPDATE Basket
        SET total_amount = (SELECT SUM(total_amount) FROM BasketItem WHERE basket_id = %s),
            total_quantity = (SELECT SUM(quantity) FROM BasketItem WHERE basket_id = %s)
        WHERE pk = %s
        """
        cursor.execute(update_basket_query, (basket[0], basket[0], basket[0]))

        connection.commit()

        # Return the updated basket
        return jsonify(build_basket_object(user_id))
    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
@app.route("/web/basket/add-item-to-basket", methods=["POST"])
def add_item_to_basket():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 401

    try:
        # Decode the refresh token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")

        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 401
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        # Get the productPk and quantity from the request body
        data = request.json
        product_pk = data.get("productPk")
        quantity = data.get("quantity")

        if not product_pk or not quantity:
            return jsonify({"error": "Missing productPk or quantity"}), 400

        # Get a database connection
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check if a basket exists for the user
        basket_query = """
        SELECT pk FROM Basket WHERE user_id = %s
        """
        cursor.execute(basket_query, (user_id,))
        basket = cursor.fetchone()

        # If a basket doesn't exist, create one
        if not basket:
            create_basket_query = """
            INSERT INTO Basket (user_id, total_amount, total_quantity)
            VALUES (%s, 0, 0)
            """
            cursor.execute(create_basket_query, (user_id,))
            connection.commit()

            # Get the pk of the new basket
            cursor.execute(basket_query, (user_id,))
            basket = cursor.fetchone()

        if basket:
            # Get the price, currency_type and stock of the product
            product_query = """
            SELECT price, currency_type, in_stock FROM products WHERE pk = %s
            """
            cursor.execute(product_query, (product_pk,))
            product = cursor.fetchone()

            if not product:
                return jsonify({"error": "Product not found"}), 404

            price, currency_type, stock = product
            price = float(price)
            quantity = int(quantity)
            stock = int(stock)

            if price == 0:
                return jsonify({"error": "Product price is zero"}), 400

            # Check if there is enough stock of the product
            if stock < quantity:
                return jsonify({"error": "Not enough stock","quantity_requested":quantity,"in_stock":stock}), 400

            # Check if a BasketItem exists with the given basket_id and product
            check_query = """
            SELECT id, quantity FROM BasketItem
            WHERE basket_id = %s
            AND product = %s
            """
            cursor.execute(check_query, (basket[0], product_pk))
            item = cursor.fetchone()

            if item:
                if item[1] + quantity > stock:
                    return jsonify({"error": "Not enough stock","quantity_requested":quantity,"quantity":item[1],"stock":stock}), 400
                # If a BasketItem exists, increment its quantity
                update_query = """
                UPDATE BasketItem
                SET quantity = quantity + %s, total_amount = total_amount + price * %s
                WHERE id = %s
                """
                cursor.execute(update_query, (quantity, quantity, item[0]))
            else:
                # If no BasketItem exists, insert a new one
                insert_query = """
                INSERT INTO BasketItem (stock, quantity, product, total_amount, price, currency_type, basket_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (stock, quantity, product_pk, price * quantity, price, currency_type, basket[0]))

            # Update the total_amount and total_quantity in the Basket table
            update_basket_query = """
            UPDATE Basket
            SET total_amount = (SELECT SUM(total_amount) FROM BasketItem WHERE basket_id = %s),
                total_quantity = (SELECT SUM(quantity) FROM BasketItem WHERE basket_id = %s)
            WHERE pk = %s
            """
            cursor.execute(update_basket_query, (basket[0], basket[0], basket[0]))

            connection.commit()

            # Return the updated basket
            return jsonify(build_basket_object(user_id))
        else:
            return jsonify({"error": "Basket not found"}), 404
    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
@app.route("/web/basket/get-basket", methods=["GET"])
def get_basket():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 400

    try:
        # Decode the refresh token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")

        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 400
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 400

        # Get a database connection
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check if a basket exists for the user
        basket_query = """
        SELECT pk FROM Basket WHERE user_id = %s
        """
        cursor.execute(basket_query, (user_id,))
        basket = cursor.fetchone()

        if basket:
            # Return the basket
            return jsonify(build_basket_object(user_id))
        else:
            return jsonify({"error": "Basket not found"}), 404
    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
#debian curl -X DELETE -H "Content-Type: application/json" --cookie "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYzljMzk2MjRiNzU3ZTlkMzI5YzhkOTM1YjQwYTdmZTYwNTM3ZjFhNzAzNDk3MWEzIiwiZXhwIjoxNzEzMjI4MTcxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.D54pJKT7UuiWsjLlV-KN4c9aaNLGok8gd__wNZM2wRs" http://wowtasker.io/web/basket/clearBasket
#windows curl -X DELETE -H "Content-Type: application/json" --cookie "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYzljMzk2MjRiNzU3ZTlkMzI5YzhkOTM1YjQwYTdmZTYwNTM3ZjFhNzAzNDk3MWEzIiwiZXhwIjoxNzEzMjI4MTcxLCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.D54pJKT7UuiWsjLlV-KN4c9aaNLGok8gd__wNZM2wRs" http://wowtasker.io/web/basket/clearBasket


@app.route("/web/basket/clear-basket", methods=["DELETE"])
def clear_basket():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 401

    try:
        # Decode the refresh token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        token_type = payload.get("token_type")

        if not token_type or token_type != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 401
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        # Get a database connection
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check if a basket exists for the user
        basket_query = """
        SELECT pk FROM Basket WHERE user_id = %s
        """
        cursor.execute(basket_query, (user_id,))
        basket = cursor.fetchone()

        if basket:
            # Delete all BasketItems for the user's basket
            delete_query = """
            DELETE FROM BasketItem WHERE basket_id = %s
            """
            cursor.execute(delete_query, (basket[0],))

            connection.commit()

            return jsonify({"message": "Basket items deleted successfully"}),200
        else:
            return jsonify({"error": "Basket not found"}), 404
    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401


def build_invoice_object(invoice_id):
    # Get the invoice information from the BTCPay Server API
    # print("invice: " + str(invoice_id))
    headers = {
        'Authorization': 'token ' + api_key, 
        'Content-Type': 'application/json'
    }
    response = requests.get(f'{btcpay_url}/stores/{store_id}/invoices/{invoice_id}', headers=headers)
    if response.status_code != 200:
        raise Exception("Failed to get BTCPay invoice")
    info = check_invoice_info(btcpay_url, store_id, invoice_id, api_key)
    invoice = response.json()
    for i in info:
        bip21_uri = i.get('paymentLink')
        if bip21_uri:
            qr_code_path = f'static/qrcodes/{invoice_id}.png'  # Use a relative path
            if not os.path.exists(qr_code_path):
                create_qr_code(bip21_uri, invoice_id)
                i['qr_code'] = f'https://wowtasker.io/{qr_code_path}'
            else:
                i['qr_code'] = f'https://wowtasker.io/{qr_code_path}'

    # Merge the invoice and info dictionaries
    merged = invoice.copy()
    for d in info:
        merged.update(d)

    return merged
def build_order_object(order_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    # Get the order details
    order_query = """
    SELECT order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id
    FROM Orders
    WHERE order_id = %s
    """
    cursor.execute(order_query, (order_id,))
    order = cursor.fetchone()

    if not order:
        return jsonify({"error": "Order not found"}), 404

    # Get the current invoice status from BTCPay
    invoice_id = order[11]  # Extract the invoice_id from the order
    invoice = build_invoice_object(invoice_id)
    invoice_status = invoice.get('status')
    invoice_status_code = invoice_status_lookup.get(invoice_status, {}).get('code')
    if invoice_status_code is None:
        return jsonify({"error": f"Invalid invoice status: {invoice_status}"}), 400

    # Update the OrderStatus in the Orders table with the current invoice status
    update_order_status_query = """
    UPDATE Orders
    SET orderStatus = %s
    WHERE order_id = %s
    """
    cursor.execute(update_order_status_query, (invoice_status_code, order_id))
    connection.commit()

    # Get the order items
    items_query = """
    SELECT id, status, currency, product, quantity, order_id, unit_price, price, createdDate
    FROM OrderItems
    WHERE order_id = %s
    """
    cursor.execute(items_query, (order[0],))
    items = cursor.fetchall()

    # Build the order object
    order_object = {
        "orderId": order[0],
        "orderNumber": order[1],
        "currency": order[2],
        "totalAmount": str(order[3]),
        "createdDate": order[4].isoformat(),
        "orderStatus": order[5],
        "orderStatusLabel": invoice_status_code_lookup.get(int(order[5]), {"code": None, "text": "Unknown status"}),
        "paymentOption": order[7],
        "user_email": order[8],
        "user": order[9],
        "basket": order[10],
        "invoiceStatus": invoice_status,  # Add the invoice status to the order object
        "orderItems": []
    }
    total_quantity = 0

   # Add the order items to the orderItems in the order object
    for item in items:
        # Get the product details from the Products table
        select_product_query = """
        SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
        FROM products p
        LEFT JOIN product_images pi ON p.pk = pi.product_id
        LEFT JOIN product_features pf ON p.pk = pf.product_id
        LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
        WHERE p.pk = %s
        """
        cursor.execute(select_product_query, (item[3],))
        product_rows = cursor.fetchall()

        # Prepare the product details for JSON response
        product_details = build_product_details(product_rows[0])
        for product_row in product_rows[1:]:
            if product_row[8] and product_row[9]:  # If there's a feature
                product_details["attributes"][product_row[8]] = {"label": product_row[9], "value": product_row[10]}
            if product_row[11]:  # If there's an additional image URL
                product_details["images"].append({"url": product_row[11], "alt_text": product_row[12]})

        total_quantity += item[4]
        order_object["orderItems"].append({
            "id": item[0],
            "status": item[1],
            "currency": item[2],
            "product": product_details,
            "quantity": item[4],
            "order": item[5],
            "unit_price": str(item[6]),
            "price": str(item[7]),
            "createdDate": item[8].isoformat()
        })
        order_object['totalQuantity'] = total_quantity
        order_object['productList'] = order_object['orderItems']
    cursor.close()
    connection.close()
    return order_object
def build_archived_order(order_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    # Get the archived order details
    order_query = """
    SELECT order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id, invoice_status
    FROM Archived_Orders
    WHERE order_id = %s
    """
    cursor.execute(order_query, (order_id,))
    order = cursor.fetchone()

    if not order:
        return jsonify({"error": "Archived order not found"}), 404

    # Get the order items
    items_query = """
    SELECT id, status, currency, product, quantity, order_id, unit_price, price, createdDate
    FROM Archived_OrderItems
    WHERE order_id = %s
    """
    cursor.execute(items_query, (order[0],))
    items = cursor.fetchall()

    # Build the archived order object
    order_object = {
        "orderId": order[0],
        "orderNumber": order[1],
        "currency": order[2],
        "totalAmount": str(order[3]),
        "createdDate": order[4].isoformat(),
        "orderStatus": order[5],
        "orderStatusLabel": invoice_status_code_lookup.get(int(order[5]), {"code": None, "text": "Unknown status"}),
        "paymentOption": order[7],
        "user_email": order[8],
        "user": order[9],
        "basket": order[10],
        "invoiceStatus": order[12],  # Get the invoice status from the order
        "orderItems": []
    }
    total_quantity = 0

    # Add the order items to the orderItems in the order object
    for item in items:
        # Get the product details from the Products table
        select_product_query = """
        SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
        FROM products p
        LEFT JOIN product_images pi ON p.pk = pi.product_id
        LEFT JOIN product_features pf ON p.pk = pf.product_id
        LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
        WHERE p.pk = %s
        """
        cursor.execute(select_product_query, (item[3],))
        product_rows = cursor.fetchall()

        # Prepare the product details for JSON response
        
        # Prepare the product details for JSON response
        if product_rows:
            product_details = build_product_details(product_rows[0])
            for product_row in product_rows[1:]:
                if product_row[8] and product_row[9]:  # If there's a feature
                    product_details["attributes"][product_row[8]] = {"label": product_row[9], "value": product_row[10]}
                if product_row[11]:  # If there's an additional image URL
                    product_details["images"].append({"url": product_row[11], "alt_text": product_row[12]})
        else:
            product_details = {
                "pk": "999",
                "name": "Invalid Product",
                "description": "Invalid Product",
                "short_description": "Invalid Product",
                "price": "0",
                "retail_price": "0",
                "currency_type": "USD",
                "currency_symbol": "$",
                "in_stock": False,
                "attributes": {},
                "images": []
            }
        if product_rows:
            total_quantity += item[4]
            order_object["orderItems"].append({
                "id": item[0],
                "status": item[1],
                "currency": item[2],
                "product": product_details,
                "quantity": item[4],
                "order": item[5],
                "unit_price": str(item[6]),
                "price": str(item[7]),
                "createdDate": item[8].isoformat()
            })
            order_object['totalQuantity'] = total_quantity
            order_object['productList'] = order_object['orderItems']
    cursor.close()
    connection.close()
    return order_object
@app.route("/web/orders/fetch-order-status", methods=["GET"])
def fetch_checkout_result():
    # Get the order associated with the token
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # Get the token from the request body
        token = request.args.get("token")

        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get the refresh_token from the headers
        refresh_token = request.cookies.get('refresh_token')
        print (request.headers)
        if not refresh_token:
            return jsonify({"error": "Missing refresh_token"}), 400

        # Decode the refresh_token to get the user_id
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")

        if not user_id:
            return jsonify({"error": "Invalid refresh_token"}), 401

        # Check the Orders table for the order
        order_query = """
        SELECT order_id
        FROM Orders
        WHERE user = %s AND order_id = %s
        """
        cursor.execute(order_query, (user_id, token))
        order = cursor.fetchone()

        if not order:
            # If the order is not found in the Orders table, check the Archived_Orders table
            archived_order_query = """
            SELECT order_id
            FROM Archived_Orders
            WHERE user = %s AND order_id = %s
            """
            cursor.execute(archived_order_query, (user_id, token))
            order = cursor.fetchone()

            if not order:
                return jsonify({"error": "Order not found"}), 404

            # Build and return the archived order object
            return jsonify(build_archived_order(order[0]))

        # Build and return the order object
        return jsonify(build_order_object(order[0]))

    except jwt.PyJWTError as e:
        # Handle decoding errors (e.g., token expired or invalid)
        return jsonify({"error": "Invalid refresh_token", "details": str(e)}), 401
    finally:
        if cursor: cursor.close()
        if connection: connection.close()

@app.route("/web/orders/checkout", methods=["POST"])
def checkout():
    cursor = None
    connection = None
    refresh_token = request.cookies.get("refresh_token")
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401

        # Generate a new access token

    except jwt.PyJWTError:
        return jsonify({"error": "Invalid refresh token"}), 401

    try:
        # Get the user_id and basket_id from the request body
        
        connection = get_db_connection()
        cursor = connection.cursor()

        # Get the basket_id for the user
        select_basket_query = """
        SELECT pk
        FROM Basket
        WHERE user_id = %s
        """
        cursor.execute(select_basket_query, (user_id,))
        basket = cursor.fetchone()
        if not basket:
            return jsonify({"error": "No basket found for this user"}), 404
        basket_id = basket[0]
        # Get any existing orders with a status of 1 for the user
        select_order_query = """
        SELECT order_id,invoice_id
        FROM Orders
        WHERE user = %s AND orderStatus = 100
        """
        cursor.execute(select_order_query, (user_id,))
        orders = cursor.fetchall()

         # If there's an existing order, build the order object and return it
        if orders:
            order_id = orders[0][0]
            invoice_id=orders[0][1]
            order_object = build_order_object(order_id)
            invoice_object = build_invoice_object(invoice_id)
            order_object["invoice"] = invoice_object
            return jsonify(order_object)


        # Get the user_email from the Users table
        select_user_query = """
        SELECT email
        FROM users
        WHERE user_id = %s
        """
        cursor.execute(select_user_query, (user_id,))
        user_email = cursor.fetchone()[0]

        # Get the items in the basket and calculate the total price
        select_items_query = """
        SELECT product, quantity, price
        FROM BasketItem
        WHERE basket_id = %s
        """
        cursor.execute(select_items_query, (basket_id,))
        items = cursor.fetchall()
        total_price = float(sum(item[1] * item[2] for item in items))

       
        headers = {
            'Authorization': 'token ' + api_key, 
            'Content-Type': 'application/json'
        }
        invoice_data = {
            "amount": total_price,
            "currency": "USD",
            # add any other necessary invoice data
        }
        response = requests.post(f'{btcpay_url}/stores/{store_id}/invoices', headers=headers, json=invoice_data)
        if response.status_code != 200:
            raise Exception("Failed to create BTCPay invoice")

        invoice = response.json()
        if 'id' in invoice:
            invoice_id = invoice['id']
        else:
            print("The 'id' key is not in the invoice dictionary.")
        invoice_id = invoice['id']

        insert_order_query = """
        INSERT INTO Orders (user, basket, user_email, invoice_id, totalAmount)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_order_query, (user_id, basket_id, user_email, invoice_id, total_price))
        order_id = cursor.lastrowid

        # Add the items to the order
        
        for item in items:
            # Get the product details from the Products table
            select_product_query = """
            SELECT name, price
            FROM products
            WHERE pk = %s
            """
            cursor.execute(select_product_query, (item[0],))
            product = cursor.fetchone()

            # Calculate the total price for the item
            total_price = item[1] * product[1]

            insert_item_query = """
            INSERT INTO OrderItems (order_id, product, quantity, name, unit_price, price, currency)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_item_query, (order_id, item[0], item[1], product[0], product[1], total_price, 'USD'))
        connection.commit()

        order_object = build_order_object(order_id)
        invoice_object = build_invoice_object(invoice_id)
        order_object["invoice"] = invoice_object
        return jsonify(order_object)

    except Exception as e:
        print(f"An error occurred: {e}")
        print(traceback.format_exc())
        return jsonify({"error": f"Something went wrong: {e}"}), 500
    finally:
        if cursor: 
            cursor.close()
        if connection: connection.close()
# @app.route("/web/orders/checkout", methods=["POST"])
# def checkout():
#     cursor = None
#     connection = None
#     refresh_token = request.cookies.get("refresh_token")
#     try:
#         payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
#         user_id = payload.get("user_id")
#         if not user_id:
#             return jsonify({"error": "Invalid refresh token"}), 401

#         # Generate a new access token

#     except jwt.PyJWTError:
#         return jsonify({"error": "Invalid refresh token"}), 401

#     try:
#         # Get the user_id and basket_id from the request body
        
#         connection = get_db_connection()
#         cursor = connection.cursor()

#         # Get the basket_id for the user
#         select_basket_query = """
#         SELECT pk
#         FROM Basket
#         WHERE user_id = %s
#         """
#         cursor.execute(select_basket_query, (user_id,))
#         basket = cursor.fetchone()
#         if not basket:
#             return jsonify({"error": "No basket found for this user"}), 404
#         basket_id = basket[0]
#         # Get any existing orders with a status of 1 for the user
#         select_order_query = """
#         SELECT order_id
#         FROM Orders
#         WHERE user = %s AND orderStatus = 100
#         """
#         cursor.execute(select_order_query, (user_id,))
#         orders = cursor.fetchall()

#         # Delete the associated items from OrderItems for each order
#         for order in orders:
#             delete_items_query = """
#             DELETE FROM OrderItems
#             WHERE order_id = %s
#             """
#             cursor.execute(delete_items_query, (order[0],))

#         # Now you can delete the orders from Orders
#         delete_order_query = """
#         DELETE FROM Orders
#         WHERE user = %s AND orderStatus = 100
#         """
#         cursor.execute(delete_order_query, (user_id,))

#         # Get the user_email from the Users table
#         select_user_query = """
#         SELECT email
#         FROM users
#         WHERE user_id = %s
#         """
#         cursor.execute(select_user_query, (user_id,))
#         user_email = cursor.fetchone()[0]

#         # Get the items in the basket and calculate the total price
#         select_items_query = """
#         SELECT product, quantity, price
#         FROM BasketItem
#         WHERE basket_id = %s
#         """
#         cursor.execute(select_items_query, (basket_id,))
#         items = cursor.fetchall()
#         total_price = float(sum(item[1] * item[2] for item in items))

       
#         headers = {
#             'Authorization': 'token ' + api_key, 
#             'Content-Type': 'application/json'
#         }
#         invoice_data = {
#             "amount": total_price,
#             "currency": "USD",
#             # add any other necessary invoice data
#         }
#         response = requests.post(f'{btcpay_url}/stores/{store_id}/invoices', headers=headers, json=invoice_data)
#         if response.status_code != 200:
#             raise Exception("Failed to create BTCPay invoice")

#         invoice = response.json()
#         if 'id' in invoice:
#             invoice_id = invoice['id']
#         else:
#             print("The 'id' key is not in the invoice dictionary.")
#         invoice_id = invoice['id']

#         insert_order_query = """
#         INSERT INTO Orders (user, basket, user_email, invoice_id, totalAmount)
#         VALUES (%s, %s, %s, %s, %s)
#         """
#         cursor.execute(insert_order_query, (user_id, basket_id, user_email, invoice_id, total_price))
#         order_id = cursor.lastrowid

#         # Add the items to the order
        
#         for item in items:
#             # Get the product details from the Products table
#             select_product_query = """
#             SELECT name, price
#             FROM products
#             WHERE pk = %s
#             """
#             cursor.execute(select_product_query, (item[0],))
#             product = cursor.fetchone()

#             # Calculate the total price for the item
#             total_price = item[1] * product[1]

#             insert_item_query = """
#             INSERT INTO OrderItems (order_id, product, quantity, name, unit_price, price, currency)
#             VALUES (%s, %s, %s, %s, %s, %s, %s)
#             """
#             cursor.execute(insert_item_query, (order_id, item[0], item[1], product[0], product[1], total_price, 'USD'))
#         connection.commit()

#         order_object = build_order_object(order_id)
#         invoice_object = build_invoice_object(invoice_id)
#         order_object["invoice"] = invoice_object
#         return jsonify(order_object)

#     except Exception as e:
#         print(f"An error occurred: {e}")
#         print(traceback.format_exc())
#         return jsonify({"error": f"Something went wrong: {e}"}), 500
#     finally:
#         if cursor: 
#             cursor.close()
#         if connection: connection.close()
@app.route("/web/user/orders", methods=["GET"])
def user_orders():
    refresh_token = request.cookies.get("refresh_token")
    try:
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

    connection = get_db_connection()
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
    if connection: connection.close()

    # Build the order objects and merge the lists
    active_orders = [build_order_object(order_id) for order_id in active_order_ids]
    archived_orders = [build_archived_order(order_id) for order_id in archived_order_ids]
    orders = active_orders + archived_orders

    total_count = archived_order_count + active_order_count
    page_count = total_count // limit if limit else 1

    return jsonify({
        "total_count": total_count,
        "page_count": page_count,
        "data": orders
    })
# @app.route("/web/user/orders", methods=["GET"])
# def user_orders():
#     refresh_token = request.cookies.get("refresh_token")
#     try:
#         payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
#         user_id = payload.get("user_id")
#         if not user_id:
#             return jsonify({"error": "Invalid refresh token"}), 401
#     except jwt.PyJWTError:
#         return jsonify({"error": "Invalid refresh token"}), 401

#     limit = request.args.get('limit', type=int)
#     page = request.args.get('page', type=int)

    

#     connection = get_db_connection()
#     cursor = connection.cursor()

#     count_orders_query = """
#     SELECT COUNT(*)
#     FROM Orders
#     WHERE user = %s
#     """
#     cursor.execute(count_orders_query, (user_id,))
#     total_count = cursor.fetchone()[0]
#     page_count = total_count // limit if limit else 1

#     select_orders_query = """
#     SELECT order_id
#     FROM Orders
#     WHERE user = %s
#     ORDER BY createdDate DESC
#     """
#     if limit is not None and page is not None:
#         select_orders_query += "LIMIT %s OFFSET %s"
#         cursor.execute(select_orders_query, (user_id, limit, (page-1)*limit))
#     else:
#         cursor.execute(select_orders_query, (user_id,))

#     order_ids = [order[0] for order in cursor.fetchall()]

#     if cursor: 
#         cursor.close()
#     if connection: connection.close()

#     orders = [build_order_object(order_id) for order_id in order_ids]
#     return jsonify({
#         "total_count": total_count,
#         "page_count": page_count,
#         "data": orders
#     })
@app.route("/web/user/get-active-order", methods=["GET"])
def user_active_order():
    refresh_token = request.cookies.get("refresh_token")
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401
    except jwt.PyJWTError:
        return jsonify({"error": "Invalid refresh token"}), 401

    connection = get_db_connection()
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
    if connection: connection.close()

    order = build_order_object(order_id[0])
    return jsonify(order)
@app.route("/web/user/order/<order_id>", methods=["GET"])
def user_order(order_id):
    refresh_token = request.cookies.get("refresh_token")
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid refresh token"}), 401
    except jwt.PyJWTError:
        return jsonify({"error": "Invalid refresh token"}), 401

    connection = get_db_connection()
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
            order_object = build_archived_order(order[0])
    else:
        order_object = build_order_object(order[0])

    if cursor: 
        cursor.close()
    if connection: connection.close()

    if order_object is None:
        return jsonify({"error": "Order not found"}), 404

    
    return jsonify(order_object)

@app.route('/web/confirminvoice', methods=['POST'])
def confirm_invoice():
    data = request.json
    # print(data)
    if data['type'] == 'InvoiceSettled':
        invoice_id = data['invoiceId']
        print(invoice_id)
        try:
            connection = get_db_connection()

            cursor = connection.cursor()
            # Get the order associated with the invoice
            select_order_query = "SELECT * FROM Orders WHERE invoice_id = %s;"
            cursor.execute(select_order_query, (invoice_id,))
            order = cursor.fetchone()
            if order:
                # Insert the order into Archived_Orders
                archived_order = order[:5] + (400,) + order[6:]

                insert_order_query = """
                INSERT INTO Archived_Orders (order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id, timestamp, invoice_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'settled');
                """
                cursor.execute(insert_order_query, archived_order)
                connection.commit()  # Commit the transaction
                
                # Get the OrderItems associated with the order
                select_order_items_query = "SELECT * FROM OrderItems WHERE order_id = %s;"
                cursor.execute(select_order_items_query, (order[0],))
                order_items = cursor.fetchall()
                allocated_licenses = 0
                for item in order_items:
                    # Insert the order item into Archived_OrderItems
                    insert_order_item_query = """
                    INSERT INTO Archived_OrderItems (id, status, currency, product, quantity, order_id, unit_price, price, createdDate, name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """
                    cursor.execute(insert_order_item_query, item)
                    connection.commit()  # Commit the transaction
                    
                    # Allocate an unlocker license for each product in the order
                    sendemail("earshelh@gmail.com","Allocating licenses","Allocating " + str(item[4]) + " licenses for " + get_product_name(item[3]) + " to user.")
                    success, num_allocated = allocate_license(order[9], item[3], item[4])
                    if success:
                        allocated_licenses += num_allocated
                
                #delete the order from the original table
                delete_order_items_query = "DELETE FROM OrderItems WHERE order_id = %s;"
                delete_order_query = "DELETE FROM Orders WHERE order_id = %s;"
                cursor.execute(delete_order_items_query, (order[0],))
                cursor.execute(delete_order_query, (order[0],))
                connection.commit()

                # Clear the basket
                delete_basket_items_query = "DELETE FROM BasketItem WHERE basket_id = %s;"
                delete_basket_query = "DELETE FROM Basket WHERE pk = %s;"
                print(order[10])
                cursor.execute(delete_basket_items_query, (order[10],))
                cursor.execute(delete_basket_query, (order[10],))
                connection.commit()  # Commit the transaction
                
               
                
                return jsonify({"success": "Order archived and licenses allocated successfully", "order": order, "order_items": order_items, "allocated_licenses": allocated_licenses}), 200
            else:
                return jsonify({"error": "No order associated with the provided invoice id"}), 400
        except mariadb.Error as error:
            print("Database error:", error)
        finally:
            if cursor: cursor.close()
            if connection: connection.close()
        
        # send_payment_confirmation_email("earshelh@gmail.com", "Earshy", "WoWTasker 30-Day", invoice_id)
    return '', 200
@app.route('/web/invoice-expired', methods=['POST'])
def invoice_expired():
    data = request.json
    if data['type'] == 'InvoiceExpired' or data['type'] == 'InvoiceInvalid':
        order_status = 400
        if data['type'] == "InvoiceExpired":
            order_status = 500
        invoice_id = data['invoiceId']
        try:
            connection = get_db_connection()

            cursor = connection.cursor()
            # Get the order associated with the invoice
            select_order_query = "SELECT * FROM Orders WHERE invoice_id = %s;"
            cursor.execute(select_order_query, (invoice_id,))
            order = cursor.fetchone()
            if order:
                # Insert the order into Archived_Orders
                insert_order_query = """
                INSERT INTO Archived_Orders (order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id, timestamp, invoice_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'expired');
                """
                archived_order = order[:5] + (order_status,) + order[6:]

                
                cursor.execute(insert_order_query, archived_order)

                
                # Get the OrderItems associated with the order
                select_order_items_query = "SELECT * FROM OrderItems WHERE order_id = %s;"
                cursor.execute(select_order_items_query, (order[0],))
                order_items = cursor.fetchall()
                for item in order_items:
                    # Insert the order item into Archived_OrderItems
                    
                    insert_order_item_query = """
                    INSERT INTO Archived_OrderItems (id, status, currency, product, quantity, order_id, unit_price, price, createdDate, name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """
                    cursor.execute(insert_order_item_query, item)
                
                # Delete the order and order items from the original tables
                delete_order_items_query = "DELETE FROM OrderItems WHERE order_id = %s;"
                delete_order_query = "DELETE FROM Orders WHERE order_id = %s;"
                cursor.execute(delete_order_items_query, (order[0],))
                cursor.execute(delete_order_query, (order[0],))
                
                connection.commit()
                return jsonify({"success": "Order archived successfully", "order": order, "order_items": order_items}), 200
            else:
                
                return jsonify({"error": "No order associated with the provided invoice id"}), 400
        except mariadb.Error as error:
            print("Database error:", error)
        finally:
            if cursor: cursor.close()
            if connection: connection.close()
        
    return '', 200
def check_invoice_status(btcpay_url, store_id, invoice_id, api_key):
    headers = {
        'Authorization': 'token ' + api_key, 
        'Content-Type': 'application/json'
    }

    response = requests.get(f'{btcpay_url}/stores/{store_id}/invoices/{invoice_id}', headers=headers)

    if response.status_code == 200:
        return response.json()['status']
    else:
        return None
def check_invoice_info(btcpay_url, store_id, invoice_id, api_key):
    headers = {
        'Authorization': 'token ' + api_key,
        'Content-Type': 'application/json'
    }
    
    # Corrected API URL
    api_url = f'{btcpay_url}/stores/{store_id}/invoices/{invoice_id}/payment-methods'
    # print(api_url)
    response = requests.get(api_url, headers=headers)
    
    # Print the used API URL for debugging purposes
    # print(f'Requested URL: {api_url}')
    
    # Check if the response was successful
    if response.status_code == 200:
        return response.json()
    else:
        print(f'Failed to retrieve data: Status code {response.status_code}')
        return None
@app.route("/web/orders/invoice-info/<invoice_id>", methods=["GET"])
def invoice_info(invoice_id):
    if not invoice_id:
        return jsonify({"error": "Missing invoice_id"}), 400

    info = check_invoice_info(btcpay_url, store_id, invoice_id, api_key)
    # print(info)
    if info is None:
        return jsonify({"error": "Failed to get invoice info"}), 500

    
    return info

@app.route("/web/orders/invoice_status/<invoice_id>", methods=["GET"])
def invoice_status(invoice_id):
    if not invoice_id:
        return jsonify({"error": "Missing invoice_id"}), 400

    status = check_invoice_status(btcpay_url, store_id, invoice_id, api_key)
    if status is None:
        return jsonify({"error": "Failed to get invoice status"}), 500

    status_info = invoice_status_lookup.get(status, {"code": None, "text": "Unknown status"})
    return jsonify({"code": status_info["code"], "text": status_info["text"],"full_info":invoice_status_lookup})
@app.route("/", defaults={"u_path": ""})  # type: ignore
@app.route("/<path:u_path>")  # type: ignore
def catch_all(u_path: str):  # pylint: disable=unused-argument
    abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("2000"), debug=True)
