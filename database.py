# db_connection.py

import mariadb
from mariadb import Error

class DatabaseConnector:
    def __init__(self):
        self.config = {
            'user': 'admin',
            'password': 'hwH}FjY48Rx?*TRzk0x`>oL=~na@,e',
            'host': '127.0.0.1',
            'database': 'tasker_login',
            'port': 3306  # Assuming default MariaDB/MySQL port, specify if different
        }

    def get_db_connection (self):
        """Attempts to establish a database connection using the provided configuration."""
        try:
            connection = mariadb.connect(**self.config)
            print("Database connection successfully established.")
            return connection
        except Error as e:
            print(f"The error '{e}' occurred while attempting to connect to the database.")
            return None
