from flask import Blueprint, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from handlers import UsersHandler, AppHandler

usersBlueprint = Blueprint("usersBlueprint", __name__)
limiter = Limiter(app=AppHandler.app, key_func=get_remote_address)


@usersBlueprint.route("/delete", methods=["POST"])
def delete_user():
    return UsersHandler.deleteUser(request)


@AppHandler.app.route("/register", methods=["POST"])
@limiter.limit("2/minute")
def register():
    return UsersHandler.register(request)


@usersBlueprint.route("/confirm-delete", methods=["POST"])
def confirm_delete_user():
    return UsersHandler.confirmDeleteUser(request)


@usersBlueprint.route("/allocate-license", methods=["POST"])
def allocate_license_endpoint():
    return UsersHandler.allocateLicenseEndpoint(request)


# Registeration route is present in main.py file


@usersBlueprint.route("/confirm-registration", methods=["POST"])
def confirm_registration():
    return UsersHandler.confirmRegistration(request)


@usersBlueprint.route("/password/change", methods=["POST"])
def change_password():
    return UsersHandler.changePassword(request)


@usersBlueprint.route("/password/confirm-change", methods=["POST"])
def confirm_change_password():
    return UsersHandler.confirmChangePassword(request)


@usersBlueprint.route("/password/forgot", methods=["POST"])
def forgot_password():
    return UsersHandler.forgotPassword(request)


@usersBlueprint.route("/password/confirm-forgot", methods=["POST"])
def confirm_forgot_password():
    return UsersHandler.confirmForgotPassword(request)


@usersBlueprint.route("/login", methods=["POST"])
def weblogin():
    return UsersHandler.weblogin(request)


@usersBlueprint.route("/profile")
def current_user_profile():
    return UsersHandler.currentUserProfile(request)


@usersBlueprint.route("/orders")
def user_orders():
    return UsersHandler.userOrders(request)


@usersBlueprint.route("/get-active-order")
def user_active_order():
    return UsersHandler.userActiveOrder(request)


@usersBlueprint.route("/order/<order_id>")
def user_order(order_id):
    return UsersHandler.userOrder(request, order_id)
