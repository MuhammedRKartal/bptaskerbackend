import os
import jwt
import traceback
import requests

from flask import jsonify
from dotenv import load_dotenv
from .AppHandler import AppHandler
from .ProductsHandler import ProductsHandler
from .InvoiceHandler import InvoiceHandler

load_dotenv()

btcpay_url = os.getenv("BTCPAY_URL")
store_id = os.getenv("STORE_ID")
api_key = os.getenv("API_KEY")


class OrdersHandler:

    @classmethod
    def buildOrderObject(cls, order_id):
        connection = AppHandler.connection
        if connection is None:
            raise Exception("OrdersHandler :: buildOrderObject :: connection is None")
        cursor = connection.cursor()

        # Get the order details
        order_query = """
        SELECT order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id
        FROM Orders
        WHERE order_id = %s
        """
        cursor.execute(order_query, (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Order not found"}), 404

        # Get the current invoice status from BTCPay
        invoice_id = order[11]  # Extract the invoice_id from the order
        invoice = InvoiceHandler.buildInvoiceObject(invoice_id)
        if invoice is None:
            return jsonify({"error": "invoice build failed"})
        invoice_status = invoice.get("status")
        invoice_status_code = AppHandler.invoice_status_lookup.get(
            invoice_status, {}
        ).get("code")
        if invoice_status_code is None:
            return jsonify({"error": f"Invalid invoice status: {invoice_status}"}), 400

        # Update the OrderStatus in the Orders table with the current invoice status
        update_order_status_query = """
        UPDATE Orders
        SET orderStatus = %s
        WHERE order_id = %s
        """
        cursor.execute(update_order_status_query, (invoice_status_code, order_id))
        connection.commit()

        # Get the order items
        items_query = """
        SELECT id, status, currency, product, quantity, order_id, unit_price, price, createdDate
        FROM OrderItems
        WHERE order_id = %s
        """
        cursor.execute(items_query, (order[0],))
        items = cursor.fetchall()

        # Build the order object
        order_object = {
            "orderId": order[0],
            "orderNumber": order[1],
            "currency": order[2],
            "totalAmount": str(order[3]),
            "createdDate": order[4].isoformat(),
            "orderStatus": order[5],
            "orderStatusLabel": AppHandler.invoice_status_code_lookup.get(
                int(order[5]), {"code": None, "text": "Unknown status"}
            ),
            "paymentOption": order[7],
            "user_email": order[8],
            "user": order[9],
            "basket": order[10],
            "invoiceStatus": invoice_status,  # Add the invoice status to the order object
            "orderItems": [],
        }
        total_quantity = 0

        # Add the order items to the orderItems in the order object
        for item in items:
            # Get the product details from the Products table
            select_product_query = """
            SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
            FROM products p
            LEFT JOIN product_images pi ON p.pk = pi.product_id
            LEFT JOIN product_features pf ON p.pk = pf.product_id
            LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
            WHERE p.pk = %s
            """
            cursor.execute(select_product_query, (item[3],))
            product_rows = cursor.fetchall()

            # Prepare the product details for JSON response
            product_details = ProductsHandler.buildProductDetails(product_rows[0])
            for product_row in product_rows[1:]:
                if product_row[8] and product_row[9]:  # If there's a feature
                    product_details["attributes"][product_row[8]] = {
                        "label": product_row[9],
                        "value": product_row[10],
                    }
                if product_row[11]:  # If there's an additional image URL
                    product_details["images"].append(
                        {"url": product_row[11], "alt_text": product_row[12]}
                    )

            total_quantity += item[4]
            order_object["orderItems"].append(
                {
                    "id": item[0],
                    "status": item[1],
                    "currency": item[2],
                    "product": product_details,
                    "quantity": item[4],
                    "order": item[5],
                    "unit_price": str(item[6]),
                    "price": str(item[7]),
                    "createdDate": item[8].isoformat(),
                }
            )
            order_object["totalQuantity"] = total_quantity
            order_object["productList"] = order_object["orderItems"]
        cursor.close()
        return order_object

    @classmethod
    def buildArchivedOrder(cls, order_id):
        connection = AppHandler.connection
        if connection is None:
            raise Exception("OrdersHandler :: buildArchivedOrder :: connection is None")
        cursor = connection.cursor()

        # Get the archived order details
        order_query = """
        SELECT order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id, invoice_status
        FROM Archived_Orders
        WHERE order_id = %s
        """
        cursor.execute(order_query, (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Archived order not found"}), 404

        # Get the order items
        items_query = """
        SELECT id, status, currency, product, quantity, order_id, unit_price, price, createdDate
        FROM Archived_OrderItems
        WHERE order_id = %s
        """
        cursor.execute(items_query, (order[0],))
        items = cursor.fetchall()

        # Build the archived order object
        order_object = {
            "orderId": order[0],
            "orderNumber": order[1],
            "currency": order[2],
            "totalAmount": str(order[3]),
            "createdDate": order[4].isoformat(),
            "orderStatus": order[5],
            "orderStatusLabel": AppHandler.invoice_status_code_lookup.get(
                int(order[5]), {"code": None, "text": "Unknown status"}
            ),
            "paymentOption": order[7],
            "user_email": order[8],
            "user": order[9],
            "basket": order[10],
            "invoiceStatus": order[12],  # Get the invoice status from the order
            "orderItems": [],
        }
        total_quantity = 0

        # Add the order items to the orderItems in the order object
        for item in items:
            # Get the product details from the Products table
            select_product_query = """
            SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
            FROM products p
            LEFT JOIN product_images pi ON p.pk = pi.product_id
            LEFT JOIN product_features pf ON p.pk = pf.product_id
            LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
            WHERE p.pk = %s
            """
            cursor.execute(select_product_query, (item[3],))
            product_rows = cursor.fetchall()

            # Prepare the product details for JSON response

            # Prepare the product details for JSON response
            if product_rows:
                product_details = ProductsHandler.buildProductDetails(product_rows[0])
                for product_row in product_rows[1:]:
                    if product_row[8] and product_row[9]:  # If there's a feature
                        product_details["attributes"][product_row[8]] = {
                            "label": product_row[9],
                            "value": product_row[10],
                        }
                    if product_row[11]:  # If there's an additional image URL
                        product_details["images"].append(
                            {"url": product_row[11], "alt_text": product_row[12]}
                        )
            else:
                product_details = {
                    "pk": "999",
                    "name": "Invalid Product",
                    "description": "Invalid Product",
                    "short_description": "Invalid Product",
                    "price": "0",
                    "retail_price": "0",
                    "currency_type": "USD",
                    "currency_symbol": "$",
                    "in_stock": False,
                    "attributes": {},
                    "images": [],
                }
            if product_rows:
                total_quantity += item[4]
                order_object["orderItems"].append(
                    {
                        "id": item[0],
                        "status": item[1],
                        "currency": item[2],
                        "product": product_details,
                        "quantity": item[4],
                        "order": item[5],
                        "unit_price": str(item[6]),
                        "price": str(item[7]),
                        "createdDate": item[8].isoformat(),
                    }
                )
                order_object["totalQuantity"] = total_quantity
                order_object["productList"] = order_object["orderItems"]
        cursor.close()
        return order_object

    @classmethod
    def fetchCheckoutResult(cls, request):
        # Get the order associated with the token
        connection = AppHandler.connection
        if connection is None:
            return jsonify({"error": "Connection is None"})
        cursor = connection.cursor()
        try:
            # Get the token from the request body
            token = request.args.get("token")

            if not token:
                return jsonify({"error": "Missing token"}), 400

            # Get the refresh_token from the headers
            refresh_token = request.cookies.get("refresh_token")
            print(request.headers)
            if not refresh_token:
                return jsonify({"error": "Missing refresh_token"}), 400

            # Decode the refresh_token to get the user_id
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception(
                    "OrdersHandler :: fetchCheckoutResult :: Env vars not found"
                )
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")

            if not user_id:
                return jsonify({"error": "Invalid refresh_token"}), 401

            # Check the Orders table for the order
            order_query = """
            SELECT order_id
            FROM Orders
            WHERE user = %s AND order_id = %s
            """
            cursor.execute(order_query, (user_id, token))
            order = cursor.fetchone()

            if not order:
                # If the order is not found in the Orders table, check the Archived_Orders table
                archived_order_query = """
                SELECT order_id
                FROM Archived_Orders
                WHERE user = %s AND order_id = %s
                """
                cursor.execute(archived_order_query, (user_id, token))
                order = cursor.fetchone()

                if not order:
                    return jsonify({"error": "Order not found"}), 404

                # Build and return the archived order object
                return jsonify(cls.buildArchivedOrder(order[0]))

            # Build and return the order object
            return jsonify(cls.buildOrderObject(order[0]))

        except jwt.PyJWTError as e:
            # Handle decoding errors (e.g., token expired or invalid)
            return jsonify({"error": "Invalid refresh_token", "details": str(e)}), 401
        finally:
            if cursor:
                cursor.close()

    @classmethod
    def checkout(cls, request):
        cursor = None
        connection = None
        refresh_token = request.cookies.get("refresh_token")
        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
                raise Exception("OrdersHandler :: checkout :: Env vars not found")
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401

            # Generate a new access token

        except jwt.PyJWTError:
            return jsonify({"error": "Invalid refresh token"}), 401

        try:
            # Get the user_id and basket_id from the request body

            connection = AppHandler.connection
            if connection is None:
                raise Exception("OrdersHandler :: checkout :: connection is None")
            cursor = connection.cursor()

            # Get the basket_id for the user
            select_basket_query = """
            SELECT pk
            FROM Basket
            WHERE user_id = %s
            """
            cursor.execute(select_basket_query, (user_id,))
            basket = cursor.fetchone()
            if not basket:
                return jsonify({"error": "No basket found for this user"}), 404
            basket_id = basket[0]
            # Get any existing orders with a status of 1 for the user
            select_order_query = """
            SELECT order_id,invoice_id
            FROM Orders
            WHERE user = %s AND orderStatus = 100
            """
            cursor.execute(select_order_query, (user_id,))
            orders = cursor.fetchall()

            # If there's an existing order, build the order object and return it
            if orders:
                order_id = orders[0][0]
                invoice_id = orders[0][1]
                order_object = cls.buildOrderObject(order_id)
                invoice_object = InvoiceHandler.buildInvoiceObject(invoice_id)
                order_object["invoice"] = invoice_object
                return jsonify(order_object)

            # Get the user_email from the Users table
            select_user_query = """
            SELECT email
            FROM users
            WHERE user_id = %s
            """
            cursor.execute(select_user_query, (user_id,))
            user_email = cursor.fetchone()[0]

            # Get the items in the basket and calculate the total price
            select_items_query = """
            SELECT product, quantity, price
            FROM BasketItem
            WHERE basket_id = %s
            """
            cursor.execute(select_items_query, (basket_id,))
            items = cursor.fetchall()
            total_price = float(sum(item[1] * item[2] for item in items))

            headers = {
                "Authorization": f"token {api_key}",
                "Content-Type": "application/json",
            }
            invoice_data = {
                "amount": total_price,
                "currency": "USD",
                # add any other necessary invoice data
            }
            response = requests.post(
                f"{btcpay_url}/stores/{store_id}/invoices",
                headers=headers,
                json=invoice_data,
            )
            if response.status_code != 200:
                raise Exception("Failed to create BTCPay invoice")

            invoice = response.json()
            if "id" in invoice:
                invoice_id = invoice["id"]
            else:
                print("The 'id' key is not in the invoice dictionary.")
            invoice_id = invoice["id"]

            insert_order_query = """
            INSERT INTO Orders (user, basket, user_email, invoice_id, totalAmount)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(
                insert_order_query,
                (user_id, basket_id, user_email, invoice_id, total_price),
            )
            order_id = cursor.lastrowid

            # Add the items to the order

            for item in items:
                # Get the product details from the Products table
                select_product_query = """
                SELECT name, price
                FROM products
                WHERE pk = %s
                """
                cursor.execute(select_product_query, (item[0],))
                product = cursor.fetchone()

                # Calculate the total price for the item
                total_price = item[1] * product[1]

                insert_item_query = """
                INSERT INTO OrderItems (order_id, product, quantity, name, unit_price, price, currency)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(
                    insert_item_query,
                    (
                        order_id,
                        item[0],
                        item[1],
                        product[0],
                        product[1],
                        total_price,
                        "USD",
                    ),
                )
            connection.commit()

            order_object = cls.buildOrderObject(order_id)
            invoice_object = InvoiceHandler.buildInvoiceObject(invoice_id)
            order_object["invoice"] = invoice_object
            return jsonify(order_object)

        except Exception as e:
            print(f"An error occurred: {e}")
            print(traceback.format_exc())
            return jsonify({"error": f"Something went wrong: {e}"}), 500
        finally:
            if cursor:
                cursor.close()
