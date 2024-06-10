import os
import requests
import mariadb

from flask import jsonify

from dotenv import load_dotenv
from .UtilsHandler import UtilsHandler
from .AppHandler import AppHandler
from .LicensesHandler import LicensesHandler
from .ProductsHandler import ProductsHandler
from .EmailHandler import EmailHandler

load_dotenv()

btcpay_url = os.getenv("BTCPAY_URL")
store_id = os.getenv("STORE_ID")
api_key = os.getenv("API_KEY")


class InvoiceHandler:

    @classmethod
    def checkInvoiceInfo(cls, btcpay_url, store_id, invoice_id, api_key):
        headers = {
            "Authorization": "token " + api_key,
            "Content-Type": "application/json",
        }

        # Corrected API URL
        api_url = (
            f"{btcpay_url}/stores/{store_id}/invoices/{invoice_id}/payment-methods"
        )
        # print(api_url)
        response = requests.get(api_url, headers=headers)

        # Print the used API URL for debugging purposes
        # print(f'Requested URL: {api_url}')

        # Check if the response was successful
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to retrieve data: Status code {response.status_code}")
            return None

    @classmethod
    def buildInvoiceObject(cls, invoice_id):
        # Get the invoice information from the BTCPay Server API
        # print("invice: " + str(invoice_id))
        if (not api_key) or (not store_id) or (not btcpay_url):
            raise Exception(
                "InvoiceHandler :: buildInvoiceObject :: Env vars not found"
            )
        headers = {
            "Authorization": "token " + api_key,
            "Content-Type": "application/json",
        }
        response = requests.get(
            f"{btcpay_url}/stores/{store_id}/invoices/{invoice_id}", headers=headers
        )
        if response.status_code != 200:
            raise Exception("Failed to get BTCPay invoice")
        info = cls.checkInvoiceInfo(btcpay_url, store_id, invoice_id, api_key)
        if info is None:
            raise Exception("Invoice info retreival failed")
        invoice = response.json()
        for i in info:
            bip21_uri = i.get("paymentLink")
            if bip21_uri:
                qr_code_path = f"static/qrcodes/{invoice_id}.png"  # Use a relative path
                if not os.path.exists(qr_code_path):
                    UtilsHandler.createQrCode(bip21_uri, invoice_id)
                    i["qr_code"] = f"https://wowtasker.io/{qr_code_path}"
                else:
                    i["qr_code"] = f"https://wowtasker.io/{qr_code_path}"

        # Merge the invoice and info dictionaries
        merged = invoice.copy()
        for d in info:
            merged.update(d)

        return merged

    @classmethod
    def confirmInvoice(cls, request):
        data = request.json
        # print(data)
        if data["type"] == "InvoiceSettled":
            invoice_id = data["invoiceId"]
            print(invoice_id)
            cursor = None
            try:
                connection = AppHandler.connection
                if connection is None:
                    raise Exception(
                        "InvoiceHandler :: confirmInvoice :: connection is None"
                    )

                cursor = connection.cursor()
                # Get the order associated with the invoice
                select_order_query = "SELECT * FROM Orders WHERE invoice_id = %s;"
                cursor.execute(select_order_query, (invoice_id,))
                order = cursor.fetchone()
                if order:
                    # Insert the order into Archived_Orders
                    archived_order = order[:5] + (400,) + order[6:]

                    insert_order_query = """
                    INSERT INTO Archived_Orders (order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id, timestamp, invoice_status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'settled');
                    """
                    cursor.execute(insert_order_query, archived_order)
                    connection.commit()  # Commit the transaction

                    # Get the OrderItems associated with the order
                    select_order_items_query = (
                        "SELECT * FROM OrderItems WHERE order_id = %s;"
                    )
                    cursor.execute(select_order_items_query, (order[0],))
                    order_items = cursor.fetchall()
                    allocated_licenses = 0
                    for item in order_items:
                        # Insert the order item into Archived_OrderItems
                        insert_order_item_query = """
                        INSERT INTO Archived_OrderItems (id, status, currency, product, quantity, order_id, unit_price, price, createdDate, name)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """
                        cursor.execute(insert_order_item_query, item)
                        connection.commit()  # Commit the transaction

                        # Allocate an unlocker license for each product in the order
                        EmailHandler.__sendemail(
                            "earshelh@gmail.com",
                            "Allocating licenses",
                            f"Allocating {str(item[4])} licenses for {ProductsHandler.getProductName(item[3])} to user.",
                        )
                        success, num_allocated = LicensesHandler.allocateLicense(
                            order[9], item[3], item[4]
                        )
                        if success:
                            allocated_licenses += num_allocated

                    # delete the order from the original table
                    delete_order_items_query = (
                        "DELETE FROM OrderItems WHERE order_id = %s;"
                    )
                    delete_order_query = "DELETE FROM Orders WHERE order_id = %s;"
                    cursor.execute(delete_order_items_query, (order[0],))
                    cursor.execute(delete_order_query, (order[0],))
                    connection.commit()

                    # Clear the basket
                    delete_basket_items_query = (
                        "DELETE FROM BasketItem WHERE basket_id = %s;"
                    )
                    delete_basket_query = "DELETE FROM Basket WHERE pk = %s;"
                    print(order[10])
                    cursor.execute(delete_basket_items_query, (order[10],))
                    cursor.execute(delete_basket_query, (order[10],))
                    connection.commit()  # Commit the transaction

                    return (
                        jsonify(
                            {
                                "success": "Order archived and licenses allocated successfully",
                                "order": order,
                                "order_items": order_items,
                                "allocated_licenses": allocated_licenses,
                            }
                        ),
                        200,
                    )
                else:
                    return (
                        jsonify(
                            {
                                "error": "No order associated with the provided invoice id"
                            }
                        ),
                        400,
                    )
            except mariadb.Error as error:
                print("Database error:", error)
            finally:
                if cursor:
                    cursor.close()

            # send_payment_confirmation_email("earshelh@gmail.com", "Earshy", "WoWTasker 30-Day", invoice_id)
        return "", 200

    @classmethod
    def checkInvoiceStatus(
        cls, invoice_id, btcpay_url=btcpay_url, store_id=store_id, api_key=api_key
    ):
        headers = {
            "Authorization": f"token {api_key}",
            "Content-Type": "application/json",
        }

        response = requests.get(
            f"{btcpay_url}/stores/{store_id}/invoices/{invoice_id}", headers=headers
        )

        if response.status_code == 200:
            return response.json()["status"]
        else:
            return None

    @classmethod
    def invoiceExpired(cls, request):
        data = request.json
        if data["type"] == "InvoiceExpired" or data["type"] == "InvoiceInvalid":
            order_status = 400
            if data["type"] == "InvoiceExpired":
                order_status = 500
            invoice_id = data["invoiceId"]
            cursor = None
            try:
                connection = AppHandler.connection
                if connection is None:
                    raise Exception(
                        "InvoiceHandler :: invoiceExpired :: connection is None"
                    )

                cursor = connection.cursor()
                # Get the order associated with the invoice
                select_order_query = "SELECT * FROM Orders WHERE invoice_id = %s;"
                cursor.execute(select_order_query, (invoice_id,))
                order = cursor.fetchone()
                if order:
                    # Insert the order into Archived_Orders
                    insert_order_query = """
                    INSERT INTO Archived_Orders (order_id, orderNumber, currency, totalAmount, createdDate, orderStatus, orderStatusLabel, paymentOption, user_email, user, basket, invoice_id, timestamp, invoice_status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'expired');
                    """
                    archived_order = order[:5] + (order_status,) + order[6:]

                    cursor.execute(insert_order_query, archived_order)

                    # Get the OrderItems associated with the order
                    select_order_items_query = (
                        "SELECT * FROM OrderItems WHERE order_id = %s;"
                    )
                    cursor.execute(select_order_items_query, (order[0],))
                    order_items = cursor.fetchall()
                    for item in order_items:
                        # Insert the order item into Archived_OrderItems

                        insert_order_item_query = """
                        INSERT INTO Archived_OrderItems (id, status, currency, product, quantity, order_id, unit_price, price, createdDate, name)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """
                        cursor.execute(insert_order_item_query, item)

                    # Delete the order and order items from the original tables
                    delete_order_items_query = (
                        "DELETE FROM OrderItems WHERE order_id = %s;"
                    )
                    delete_order_query = "DELETE FROM Orders WHERE order_id = %s;"
                    cursor.execute(delete_order_items_query, (order[0],))
                    cursor.execute(delete_order_query, (order[0],))

                    connection.commit()
                    return (
                        jsonify(
                            {
                                "success": "Order archived successfully",
                                "order": order,
                                "order_items": order_items,
                            }
                        ),
                        200,
                    )
                else:

                    return (
                        jsonify(
                            {
                                "error": "No order associated with the provided invoice id"
                            }
                        ),
                        400,
                    )
            except mariadb.Error as error:
                print("Database error:", error)
            finally:
                if cursor:
                    cursor.close()

        return "", 200

    @classmethod
    def invoiceInfo(cls, invoice_id):
        if not invoice_id:
            return jsonify({"error": "Missing invoice_id"}), 400

        info = cls.checkInvoiceInfo(btcpay_url, store_id, invoice_id, api_key)
        # print(info)
        if info is None:
            return jsonify({"error": "Failed to get invoice info"}), 500

        return info

    @classmethod
    def invoiceStatus(cls, invoice_id):
        if not invoice_id:
            return jsonify({"error": "Missing invoice_id"}), 400

        status = cls.checkInvoiceStatus(btcpay_url, store_id, invoice_id, api_key)
        if status is None:
            return jsonify({"error": "Failed to get invoice status"}), 500

        status_info = AppHandler.invoice_status_lookup.get(
            status, {"code": None, "text": "Unknown status"}
        )
        return jsonify(
            {
                "code": status_info["code"],
                "text": status_info["text"],
                "full_info": AppHandler.invoice_status_lookup,
            }
        )
