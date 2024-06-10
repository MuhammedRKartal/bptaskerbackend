from flask import Blueprint, request

from handlers import OrdersHandler, InvoiceHandler

ordersBlueprint = Blueprint("ordersBlueprint", __name__)


@ordersBlueprint.route("/invoice-info/<invoice_id>")
def invoice_info(invoice_id):
    return InvoiceHandler.invoiceInfo(invoice_id)


@ordersBlueprint.route("/invoice_status/<invoice_id>")
def invoice_status(invoice_id):
    return InvoiceHandler.invoiceStatus(invoice_id)


@ordersBlueprint.route("/fetch-order-status")
def fetch_order_result():
    return OrdersHandler.fetchOrderResult(request)


@ordersBlueprint.route("/checkout", methods=["POST"])
def checkout():
    return OrdersHandler.checkout(request)
