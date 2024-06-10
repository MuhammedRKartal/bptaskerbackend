import mariadb
from flask import Flask

class AppHandler:
    _instance = None
    connection = None
    app = Flask(__name__)
    banned_username_words = [
        "admin", "administrator", "root", "superuser", "moderator", "mod",
        "staff", "support", "help", "contact", "info", "webmaster", "abuse",
        "postmaster", "hostmaster", "noc", "security", "sysadmin", "system",
        "tech", "web", "www", "ftp", "http", "https", "smtp", "pop3", "imap",
        "mail", "administator", "administrator", "tasker",
    ]
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
        500: "Expired",
    }
    CURRENCY_SYMBOLS = {
        "USD": "$", "EUR": "€", "JPY": "¥", "GBP": "£", "AUD": "$", "CAD": "$",
        "CHF": "CHF", "CNY": "¥", "SEK": "kr", "NZD": "$",
        # Add more currencies and their symbols here
    }

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, user, password, host, database) -> None:
        if AppHandler.connection is None:
            try:
                config = {
                    "user": user,
                    "password": password,
                    "host": host,
                    "database": database
                }
                AppHandler.connection = mariadb.connect(**config)
                print("CONNECTION MADE")
            except mariadb.Error as e:
                print(f"Error connecting to MariaDB Platform: {e}")
                raise Exception(f"The error '{e}' occurred")

    def __del__(self):
        if AppHandler.connection is not None:
            AppHandler.connection.close()
            print("CONNECTION BROKEN")
