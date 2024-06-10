from flask import Blueprint, request
import requests
from handlers import (
    WebHandler,
    AuthHandler,
    BasketHandler,
    TokensHandler,
    ProductsHandler,
    InvoiceHandler,
)

webBlueprint = Blueprint("webBlueprint", __name__)


@webBlueprint.route("/adduser")
def userHome():
    return WebHandler.addUser(request)


@webBlueprint.route("/verify", methods=["POST"])
def verify():
    return AuthHandler.verify(request)


@webBlueprint.route("/refresh", methods=["POST"])
def refresh_token():
    return TokensHandler.refreshToken(request)


@webBlueprint.route("/currentuser")
def current_user():
    return WebHandler.currentUser(request)


@webBlueprint.route("/products")
def get_all_products():
    return ProductsHandler.getAllProducts(request)


@webBlueprint.route("/products/<pk>")
def get_product_by_pk_or_name(pk):
    return ProductsHandler.getProductByPkOrName(pk, request)


@webBlueprint.route("/confirminvoice", methods=["POST"])
def confirm_invoice():
    return InvoiceHandler.confirmInvoice(request)


@webBlueprint.route("/invoice-expired", methods=["POST"])
def invoice_expired():
    return InvoiceHandler.invoiceExpired(request)
