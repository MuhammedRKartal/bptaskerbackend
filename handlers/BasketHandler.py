import jwt
import os

from dotenv import load_dotenv
from flask import jsonify

from .AppHandler import AppHandler
from .ProductsHandler import ProductsHandler

load_dotenv()


class BasketHandler:

    @classmethod
    def buildBasketObject(cls, user_id):
        connection = AppHandler.connection
        if connection is None:
            raise Exception("BasketHandler :: buildBasketObject :: connection is None")

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
            GROUP BY product_id, image_url
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
            "product_list": [],
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

            product_details = ProductsHandler.buildProductDetails(product_rows[0])
            for row in product_rows[1:]:
                if (
                    row[8] is not None and row[9] is not None and row[10] is not None
                ):  # If there's a feature
                    product_details["attributes"][row[8]] = {
                        "label": row[9],
                        "value": row[10],
                    }
                if row[11]:  # If there's an image URL
                    product_details["images"].append(
                        {"url": row[11], "alt_text": row[12]}
                    )

            basket_object["product_list"].append(
                {
                    "item_id": item[0],
                    "stock": item[1],
                    "quantity": item[2],
                    "product": product_details,
                    "image": item[4],
                    "total_amount": str(item[5]),
                    "price": str(item[6]),
                    "currency_type": item[7],
                    "currency_symbol": AppHandler.CURRENCY_SYMBOLS.get(item[7], ""),
                }
            )

        cursor.close()
        return basket_object

    @classmethod
    def updateQuantity(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 401

        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception("BasketHandler :: updateQuantity :: Env vars not found")
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
            connection = AppHandler.connection
            if connection is None:
                return jsonify(
                    {"error": "BasketHandler :: updateQuantity :: connection is None"}
                )
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
                return (
                    jsonify(
                        {
                            "error": "Not enough stock",
                            "quantity_requested": quantity,
                            "in_stock": stock,
                        }
                    ),
                    400,
                )

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
                return (
                    jsonify(
                        {"error": "Item not found in basket"},
                        cls.buildBasketObject(user_id),
                    ),
                    404,
                )

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
                cursor.execute(
                    update_query,
                    (quantity, price * quantity, price, currency_type, stock, item[0]),
                )

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
            return jsonify(cls.buildBasketObject(user_id))
        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401

    @classmethod
    def addItemToBasket(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 401

        try:
            # Decode the refresh token to get the user_id
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception("BasketHandler :: updateQuantity :: Env vars not found")
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
            connection = AppHandler.connection
            if connection is None:
                raise Exception(
                    "BasketHandler :: addItemToBasket :: connection is None"
                )
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
                    return (
                        jsonify(
                            {
                                "error": "Not enough stock",
                                "quantity_requested": quantity,
                                "in_stock": stock,
                            }
                        ),
                        400,
                    )

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
                        return (
                            jsonify(
                                {
                                    "error": "Not enough stock",
                                    "quantity_requested": quantity,
                                    "quantity": item[1],
                                    "stock": stock,
                                }
                            ),
                            400,
                        )
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
                    cursor.execute(
                        insert_query,
                        (
                            stock,
                            quantity,
                            product_pk,
                            price * quantity,
                            price,
                            currency_type,
                            basket[0],
                        ),
                    )

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
                return jsonify(cls.buildBasketObject(user_id))
            else:
                return jsonify({"error": "Basket not found"}), 404
        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401

    @classmethod
    def getBasket(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 400

        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception("BasketHandler :: updateQuantity :: Env vars not found")
            # Decode the refresh token to get the user_id
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            token_type = payload.get("token_type")

            if not token_type or token_type != "refresh":
                return jsonify({"error": "Invalid refresh token"}), 400
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 400

            # Get a database connection
            connection = AppHandler.connection
            if connection is None:
                raise Exception("BasketHandler :: getBasket :: ")
            cursor = connection.cursor()

            # Check if a basket exists for the user
            basket_query = """
            SELECT pk FROM Basket WHERE user_id = %s
            """
            cursor.execute(basket_query, (user_id,))
            basket = cursor.fetchone()

            if basket:
                # Return the basket
                return jsonify(cls.buildBasketObject(user_id))
            else:
                return jsonify({"error": "Basket not found"}), 404
        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401

    @classmethod
    def clearBasket(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 401

        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception("BasketHandler :: updateQuantity :: Env vars not found")
            # Decode the refresh token to get the user_id
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            token_type = payload.get("token_type")

            if not token_type or token_type != "refresh":
                return jsonify({"error": "Invalid refresh token"}), 401
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401

            # Get a database connection
            connection = AppHandler.connection
            if connection is None:
                raise Exception("BasketHandler :: clearBasket :: connection is None")
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

                return jsonify({"message": "Basket items deleted successfully"}), 200
            else:
                return jsonify({"error": "Basket not found"}), 404
        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh token", "details": str(e)}), 401
