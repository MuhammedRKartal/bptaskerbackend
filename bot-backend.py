#soudrce ~/wt_backend/.venv/bin/activate
#~/wt_backend/.venv/bin/python3 ~/wt_backend/server.py
#sudo systemctl status backend.service
#sudo systemctl restart snap.rocketchat-server.rocketchat-server

#rocket chat administrator/M)8PcDXh,yI3}.I

#https://wowtasker.io/static/TaskerControlCenter.zip
#https://wowtasker.io/static/Navigation.zip
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


auth_token = "I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz"



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



@app.route("/tl", methods=["GET"])
def tl():
    userID = request.args.get("userID")
    if not userID:
        return jsonify({"error": "Missing userID parameter"}), 400

    connection = get_db_connection()
    if connection is None:
        return jsonify({"error": "Failed to connect to the database"}), 500

    try:
        cursor = connection.cursor(dictionary=True)  # Use dictionary=True to return results as dictionaries
        # Using parameterized queries to prevent SQL Injection
        query = "SELECT * FROM tasker_licenses WHERE user_id = %s;"
        cursor.execute(query, (userID,))

        results = cursor.fetchall()
        # No need to loop and print each row, just return the results
    except mariadb.Error as e:
        print(f"Error: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        connection.close()

    # Using jsonify to return the results ensures the response is properly formatted as JSON
    return jsonify(results)

@app.route('/unlocker/get-lua-script',methods=["POST"])
def get_lua_script():
    # Get username and password from JSON body
    data = request.json
    unlocker_license = data.get("unlocker_license")
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT session_id FROM unlocker_sessions where unlocker_license_id = %s"
        cursor.execute(query, (unlocker_license,))
        sessions = cursor.fetchall()
        
        cursor.close()
        if len(sessions) == 0:
            return jsonify({"error": "No active session"}), 400

    lua_script = r'''
local addonName = "!Tasker"
local function encrypt(input, key)
    local output = {}
    for i = 1, #input do
        local inputByte = input:byte(i)
        local keyByte = key:byte((i - 1) % #key + 1)
        table.insert(output, string.char(bit.bxor(inputByte, keyByte)))
    end
    return table.concat(output)
end

local function decrypt(input, key)
    return encrypt(input, key) -- XOR is its own inverse
end

local function LoadCompressed(fileName)
    -- CP:Print("Loading " .. fileName)
    local path = tapi.GetWowDirectory() .. "interface\\addons\\" .. addonName .. "\\" .. fileName
    -- CP:Print(path)
    local contents = ""

    contents = tapi.ReadFile(path)

    local decompressedContents = decrypt(contents, "test")
    tapi.LoadStringIntoPlugin(decompressedContents)()

end

C_Timer.After(1, function()
    LoadCompressed("t.io")
end)

'''
    return lua_script
#add user to database
#requires: username, password,auth key
# adduser?username=exe&password=utiy&auth=I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz
#merdos 5a6fe760352a0397a672a6b1aae2dbf0401720204e49c9da 
#nasen bd3998f3747fb38d80a2c883faf86321c4832dc2ebb30dd9 
#insert into 'unlocker_license' 


@app.route("/unlocker/fileversion",methods=["POST"])
def file_version():
    data = request.json
    filename=data.get("filename")
    if filename:
        filepath = '/home/debian/wt_backend/static/' + filename
        file_hash_value = file_hash(filepath, 'sha256')
        if file_hash_value:
            return jsonify({"status":"OK","hash":file_hash_value}),200
        else:
            return jsonify({"status":"ERROR"}), 400 
    else:
        return jsonify({"status":"ERROR"}), 400


#add unlocker license to db
#requires unlockerLicense,userID,auth
# addunlockerlicense?userID=77f51de1b864150a014f54d153f9ec01a35581c37feac6d8&unlockerLicense=b16cacf2-3b1b-48c3-8316-64478c00a8f2&auth=I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz
# addunlockerlicense?userID=fafb57c7f0d1a3304f7a58ba66239b1c44a85313ed80c0fe&unlockerLicense=af4bda41-c751-4fd1-bbe4-0061de296437&auth=I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz
# fresh/fxluVayqpH aa5bef214efdd7c8833bafc10a3cb58b73c8b8807910463b
@app.route("/unlocker/addunlockerlicense")
def addUnlockerLicense():
    email = request.args.get("email")
    unlocker_license = request.args.get("unlockerLicense")
    auth = request.args.get("auth")

    if not user_id or not unlocker_license:
        return jsonify({"error": "Missing user ID or unlocker license"}), 400
    if not auth or (auth and auth != auth_token):
        return jsonify({"error": "Invalid auth token"}), 400

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        # First, check if the user exists
        user_exists_query = "SELECT user_id, username, email FROM users WHERE email = %s;"
        cursor.execute(user_exists_query, (email,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({"error": "User does not exist"}), 404

        # If the user exists, proceed to insert the unlocker license
        insert_query = "INSERT INTO unlocker_licenses (unlocker_license, user_id, user_name, email, enabled) VALUES (%s, %s, %s, %s, 1);"
        try:
            cursor.execute(insert_query, (unlocker_license, user[0], user[1], user[2]))
            connection.commit()
        except mariadb.IntegrityError:
            # This block catches an IntegrityError, which includes violations of UNIQUE constraints
            return jsonify({"error": "Unlocker key already exists"}), 400
        except mariadb.Error as err:
            # Handle other potential errors
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Database error"}), 500
        finally:
            cursor.close()
            connection.close()
        return jsonify({"message": "Unlocker key added successfully", "license": unlocker_license}), 200
    else:
        return jsonify({"error": "Failed to connect to the database"}), 500
#https://wowtasker.io/unlocker/addunusedunlockerlicense?auth=I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz&unlockerLicense=test
@app.route("/unlocker/addunusedunlockerlicense")
def addUnusedUnlockerLicense():
    unlocker_license = request.args.get("unlockerLicense")
    auth = request.args.get("auth")

    if not unlocker_license:
        return jsonify({"error": "unlocker license"}), 400
    if not auth or (auth and auth != auth_token):
        return jsonify({"error": "Invalid auth token"}), 400

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        # Check if the unlocker license already exists
        select_query = "SELECT unlocker_license FROM unused_unlocker_licenses WHERE unlocker_license = %s;"
        cursor.execute(select_query, (unlocker_license,))
        existing_license = cursor.fetchone()
        if existing_license:
            cursor.close()
            connection.close()
            return jsonify({"error": "Unlocker key already exists"}), 400

        # If the unlocker license does not exist, proceed to insert it
        insert_query = "INSERT INTO unused_unlocker_licenses (unlocker_license) VALUES (%s);"
        try:
            cursor.execute(insert_query, (unlocker_license, ))
            connection.commit()
        except mariadb.Error as err:
            # Handle potential errors
            print("Something went wrong: {}".format(err))
            return jsonify({"error": "Database error"}), 500
        finally:
            cursor.close()
            connection.close()
        return jsonify({"message": "Unlocker key added successfully", "license": unlocker_license}), 200
    else:
        return jsonify({"error": "Failed to connect to the database"}), 500
#https://wowtasker.io/unlocker/allocatelicense?auth=I2nWKDLDQVWMFeiMcN7vTjhusmbDmkSz&email=earshelh@gmail.com
@app.route("/unlocker/allocatelicense")
def allocateLicense():
    email = request.args.get("email")
    auth = request.args.get("auth")
    print(request.args)
    if not email:
        return jsonify({"error": "Missing email "}), 400
    if not auth or (auth and auth != auth_token):
        return jsonify({"error": "Invalid auth token"}), 400

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        # First, check if the user exists
        user_exists_query = "SELECT user_id, username, email FROM users WHERE email = %s;"
        cursor.execute(user_exists_query, (email,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({"error": "User does not exist"}), 404

        allocated = allocate_license(user[0],1,1)
        print(allocated)
        if allocated[0]:
            return jsonify({"message": "Unlocker key added successfully", "user: ": email}), 200
        else:
            return jsonify({"error": "Failed to allocate key!"}), 400
        
#authenticate user
#requires username,password
#POST only, requires {"user":"user","password":"password"}
@app.route("/unlocker/login", methods=["POST"])
def login():
    # Get username and password from JSON body
     # Get username and password from JSON body
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        # print(username)
        # Check if username is an email address
        if '@' in username:
            query = "SELECT user_id, password FROM users WHERE email = %s"
        else:
            query = "SELECT user_id, password FROM users WHERE username = %s"

        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and check_password_hash(user['password'], password):
            # Successful login
            #let's get their unlocker information to return to the launcher
            user_id = user['user_id']
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor(dictionary=True)
                query = "SELECT unlocker_license FROM unlocker_licenses WHERE user_id = %s"
                cursor.execute(query, (user_id,))
                unlocker_licenses = cursor.fetchone()
                cursor.close()
                
                #get launcher session
                
                connection.close()
                # session_id = create_launcher_session(user['user_id'])
                if user_id:
                    return jsonify({"status": "OK","message": "Login successful", "user_id": user_id,"unlocker_licenses":unlocker_licenses}), 200
        else:
            # Failed login
            return jsonify({"error": "Invalid username or password"}), 401
    else:
        return jsonify({"error": "Database connection failed"}), 500
@app.route("/unlocker/getnpcxyz", methods=["POST"])
def get_npc_xyz():
    # Get npcid from JSON body
    data = request.json
    npcid = data.get("npcid")

    if not npcid:
        return jsonify({"error": "Missing npcid"}), 400

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT position_x, position_y, position_z FROM creature WHERE id = %s"
        cursor.execute(query, (npcid,))
        positions = cursor.fetchall()
        cursor.close()
        connection.close()

        if positions:
            return jsonify({"status": "OK", "positions": positions}), 200
        else:
            return jsonify({"error": "NPC not found"}), 404
    else:
        return jsonify({"error": "Database connection failed"}), 500
@app.route("/unlocker/loginwithid", methods=["POST"])
def loginwithid():
    
    data = request.json
    user_id = data.get("user_id")
    # print(user_id)

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT username FROM users WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user:
            # Successful login
            #let's get their unlocker information to return to the launcher
            # user_id = user['user_id']
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor(dictionary=True)
                query = "SELECT unlocker_license FROM unlocker_licenses WHERE user_id = %s"
                cursor.execute(query, (user_id,))
                unlocker_licenses = cursor.fetchone()
                cursor.close()
                connection.close()
                return jsonify({"status": "OK","message": "Login successful", "user_id": user_id,"unlocker_licenses":unlocker_licenses}), 200
        else:
            # Failed login
            return jsonify({"error": "Invalid username or password"}), 401
    else:
        return jsonify({"error": "Database connection failed"}), 500

@app.route("/unlocker/terminatesessions",methods=["POST"])
def terminate_sessions():
    data = request.json
    user_id=data.get("user_id")
    if user_id:
        if terminate_all_sessions(user_id):
            return jsonify({"status":"OK"}),200
        else:
            return jsonify({"status":"ERROR"}), 400
    else:
        return jsonify({"status":"ERROR"}), 400

@app.route("/unlocker/cleanuplicenses", methods=["GET"])
def cleanup():
    BATCH_SIZE = 5  # Number of licenses to update at a time
    connection = get_db_connection()

    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
            SELECT unlocker_license 
            FROM unlocker_licenses 
            WHERE last_checked_expiry IS NULL OR last_checked_expiry < DATE_SUB(NOW(), INTERVAL 1 HOUR)
            LIMIT %s
            """
            cursor.execute(query, (BATCH_SIZE,))
            unlocker_licenses = cursor.fetchall()
            cursor.close()
            if unlocker_licenses:
                url = 'https://licensing.ohack.net/api/key/time_remaining'
                headers = {'Content-Type': 'application/json'}
                updated = 0
                for lic in unlocker_licenses:
                    key = lic["unlocker_license"]
                    data = {'key': key}
                    response = requests.post(url, data=json.dumps(data), headers=headers)
                    
                    if response.status_code == 200:
                        time_remaining = int(response.text)
                        cursor = connection.cursor(dictionary=True)
                        query = """
                        UPDATE unlocker_licenses 
                        SET expires = %s, last_checked_expiry = NOW() 
                        WHERE unlocker_license = %s
                        """
                        cursor.execute(query, (time_remaining, key,))
                        connection.commit()
                        cursor.close()
                        updated += 1
            else:
                updated = 0
        except mysql.connector.Error as error:
            print("Database error:", error)
        finally:
            connection.close()
    return jsonify({"message": "Cleanup completed.","licenses_updated":updated})
@app.route("/unlocker/getsessions",methods=["POST"])
def getSessions():
    data = request.json
    print(data)
    user_id = data.get("user_id")
    if user_id:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            query = "SELECT session_id FROM unlocker_sessions where user_id = %s"
            cursor.execute(query, (user_id,))
            sessions = cursor.fetchall()
            cursor.close()
            
            cursor = connection.cursor(dictionary=True)
            query = "SELECT unlocker_license FROM unlocker_licenses where user_id = %s"
            cursor.execute(query, (user_id,))
            unlocker_licences = cursor.fetchall()
            cursor.close()
            if unlocker_licences:
                
                num_unlocker_licenses = len(unlocker_licences)
            else:
                num_unlocker_licenses = 0

            
            if sessions:
                # print(sessions)
                # print(len(sessions))
                return jsonify({"status":"OK","sessions":sessions,"total":num_unlocker_licenses,"available":num_unlocker_licenses-len(sessions),"active":len(sessions)})
            else:
                return jsonify({"status":"OK","sessions":[],"total":num_unlocker_licenses,"available":num_unlocker_licenses-len(sessions),"active":0})
    else:
        jsonify({"error": "Missing userID"}), 400




@app.route("/unlocker/heartbeat", methods=["POST"])
def heartbeat():
    # Get username and password from JSON body
    #chek random number as well
    data = request.json
    unlocker_license = data.get("unlocker_license")
    pid = data.get("pid")
    

    
    if unlocker_license:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            query = "SELECT session_id FROM unlocker_sessions where unlocker_license_id = %s"
            cursor.execute(query, (unlocker_license,))
            session = cursor.fetchone()
            cursor.close()
            if session:
                try:
                    cursor = connection.cursor(dictionary=True)
                    # print(session.get("session_id"))
                    
                    query = "UPDATE unlocker_sessions SET last_heartbeat = NOW() WHERE session_id = %s;"
                    
                    cursor.execute(query, (session.get("session_id"),))
                    cursor.close()
                    
                    cursor = connection.cursor(dictionary=True)
                    query = "UPDATE unlocker_sessions SET pid = %s WHERE session_id = %s;"
                    
                    cursor.execute(query, (pid,session.get("session_id"),))
                    cursor.close()

                    connection.commit()
                    #here is where we could do some additional checks
                    #and where we will handle tasks and stuff
                    #like sending back commands

                    response = {"status":"OK","unlocker_license_id":unlocker_license,"commands":[]}
                    
                    return jsonify(response), 200
                except mariadb.Error as err:
                    print(f"Error: {err}")
                    response={"error":"Error!"}
                    return jsonify(response), 400
                finally:
                    cursor.close()
                    connection.close()
                
            else:
                response = {"status":"ERROR","error":"Session not authorized."}
                cursor.close()
                connection.close()
                return(jsonify(response)), 400
        
    if 1==1:
        return jsonify({"error": "Missing username or password"}), 400
@app.route("/sessions", methods=["POST"])
def sessions():
    data = request.json
    cid = data.get("cid")
    print("CID: " + cid)
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    if cid:
        
        if connection:
            try:
                if cid == "InnerTest":
                    response = {"status": "OK", "unlocker_keys": ["test_license"]}
                    return jsonify(response), 200
                
                query = "SELECT unlocker_license_id FROM unlocker_sessions where user_id = %s"
                cursor.execute(query, (cid,))
                unlocker_license_ids = [session['unlocker_license_id'] for session in cursor.fetchall()]
                
                if unlocker_license_ids:
                    response = {"status": "OK", "unlocker_keys": unlocker_license_ids}
                    return jsonify(response), 200
                else:
                    response = {"status": "ERROR", "error": "No sessions."}
                    return jsonify(response), 420

            except mariadb.Error as err:
                print(f"Error: {err}")
                response = {"status": "ERROR", "error": "Database error!"}
                return jsonify(response), 500

            finally:
                if cursor:
                    cursor.close()
                connection.close()
        else:
            response = {"status": "ERROR", "error": "Database connection error!"}
            return jsonify(response), 500
    else:
        response = {"status": "ERROR", "error": "No 'cid' provided!"}
        return jsonify(response), 400

    if 1==1:
        return jsonify({"error": "Unknown error"}), 400

    



#unused at the moment, but it queries the server for unlocker licenses
# for a specific user

@app.route("/unlocker/ul", methods=["POST"])  # Adjusted to accept POST requests
def ul():
    # Accessing JSON data sent in the request body
    data = request.json
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    connection = get_db_connection()

    try:
        if connection:
            cursor = connection.cursor(dictionary=True)
            query = "SELECT unlocker_license FROM unlocker_licenses WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            unlocker_licenses = cursor.fetchall()
            cursor.close()
            connection.close()

            # Extracting unlocker_license values into a list
            licenses_list = [row["unlocker_license"] for row in unlocker_licenses]

            # Constructing the response dictionary
            response = {
                "status": "OK",
                "unlocker_licenses": licenses_list
            }

            # print(response)



    except mariadb.Error as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()  # Ensuring the cursor is closed in a finally block

    # Returning JSON response
    return jsonify(response)

#get an unlocker session - this queries the users unlocker keys and compares them
#with unlocker keys from the active sessions. If any unlocker keys are available,
#it will create a session, then return that session to the launcher
#post only, at this time only requires user_id 

@app.route("/unlocker/getunlockersession", methods=["POST"])  # Adjusted to accept POST requests
def getunlockersession():
    #     CREATE TABLE `unlocker_sessions` (
    #   `session_id` varchar(64) PRIMARY KEY,
    #   `unlocker_license_id` char(32),
    #   `user_id` varchar(64),
    #   `pid` int,
    #   `last_heartbeat` timestamp,
    #   `created_at` timestamp
    # );

    # Accessing JSON data sent in the request body
    data = request.json
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    available_licenses = get_available_unlocker_licenses(user_id)
    
    if available_licenses and len(available_licenses) > 0:
        #create a session and return it to the launcher
        response = create_unlocker_session(available_licenses[0],user_id)
        return jsonify(response)
    else:
        response={"error":"No licenses available"}
        return jsonify(response),400
@app.route("/unlocker/getlaunchersession", methods=["POST"])  # Adjusted to accept POST requests
def getlaunchersession():
    #     CREATE TABLE `launcher_sessions` (
    #   `session_id` varchar(64) PRIMARY KEY,
    #   `user_id` varchar(64),
    #   `last_heartbeat` timestamp,
    #   `created_at` timestamp
    # );

    # Accessing JSON data sent in the request body
    data = request.json
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    available_licenses = get_available_unlocker_licenses(user_id)
    
    if available_licenses and len(available_licenses) > 0:
        #create a session and return it to the launcher
        response = create_unlocker_session(available_licenses[0],user_id)
        return jsonify(response)
    else:
        response={"error":"No licenses available"}
        return jsonify(response),400


@app.route("/", defaults={"u_path": ""})  # type: ignore
@app.route("/<path:u_path>")  # type: ignore
def catch_all(u_path: str):  # pylint: disable=unused-argument
    abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("2500"), debug=True)
