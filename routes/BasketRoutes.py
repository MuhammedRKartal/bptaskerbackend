from flask import Blueprint, request

from handlers import BasketHandler


basketBlueprint = Blueprint("basketBlueprint", __name__)


@basketBlueprint.route("/update-quantity", methods=["PUT"])
def update_quantity():
    return BasketHandler.updateQuantity(request)


@basketBlueprint.route("/add-item-to-basket", methods=["POST"])
def add_item_to_basket():
    return BasketHandler.addItemToBasket(request)


@basketBlueprint.route("/get-basket")
def get_basket():
    return BasketHandler.getBasket(request)


@basketBlueprint.route("/clear-basket", methods=["DELETE"])
def clear_basket():
    return BasketHandler.clearBasket(request)
