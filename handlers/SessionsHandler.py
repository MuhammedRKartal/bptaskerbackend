import uuid

import mariadb

from .AppHandler import AppHandler


class SessionsHandler:
    
    @classmethod
    def createUnlockerSession(cls, unlocker_license,user_id):
        #create random number to add to the session table
        #and return it to the client via heartbeat
        cursor = None
        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("SessionsHandler :: create_unlocker_session :: connection is None")

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
            if cursor is not None:
                cursor.close()
        return response

    @classmethod
    def createLauncherSession(cls, user_id):
        #create random number to add to the session table
        #and return it to the client via heartbeat
        cursor = None
        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("SessionsHandler :: create_unlocker_session :: connection is None")

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
            if cursor is not None:
                cursor.close()
        return response

    @classmethod
    def terminateAllSessions(cls, user_id):
        if not user_id:
            return
        cursor = None
        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception("SessionsHandler :: create_unlocker_session :: connection is None")

            cursor = connection.cursor()
            query = "DELETE FROM unlocker_sessions WHERE user_id = %s;"
            cursor.execute(query, (user_id,))
            connection.commit()
            response = {"status":"OK"}
        except mariadb.Error as err:
            print(f"Error: {err}")
            response={"error":"Error!"}
        finally:
            if cursor is not None:
                cursor.close()
        return response

    @classmethod
    def cleanupOldSessions(cls, connection):
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
