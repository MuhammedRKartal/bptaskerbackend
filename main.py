import os

from dotenv import load_dotenv
from flask import Flask, abort, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from handlers import AppHandler, UsersHandler
from routes import usersBlueprint, webBlueprint, ordersBlueprint, basketBlueprint

# Loading environment variables
load_dotenv()

app_handler = AppHandler(
        os.getenv("USERNAME"),
        os.getenv("PSWD"),
        os.getenv("HOST"),
        os.getenv("DB"),
    )
    
@AppHandler.app.route("/")
def hello():
    return "Page: /"


@AppHandler.app.route("/", defaults={"u_path": ""})  # type: ignore
@AppHandler.app.route("/<path:u_path>")  # type: ignore
def catch_all(u_path: str):
    abort(404)


AppHandler.app.register_blueprint(webBlueprint, url_prefix="/web")
AppHandler.app.register_blueprint(usersBlueprint, url_prefix="/web/user")
AppHandler.app.register_blueprint(ordersBlueprint, url_prefix="/web/orders")
AppHandler.app.register_blueprint(basketBlueprint, url_prefix="/web/basket")


def main():
    AppHandler.app.run(host="0.0.0.0", port=2000, debug=True)


if __name__ == "__main__":
    main()
