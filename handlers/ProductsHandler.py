from flask import jsonify

from .TokensHandler import TokensHandler
from .AppHandler import AppHandler


class ProductsHandler:

    @classmethod
    def getAllProducts(cls, request):
        cursor = None
        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception(
                    "ProductsHandler :: getAllProducts :: connection is None"
                )
            cursor = connection.cursor()

            # Modified query to also fetch product features
            query = """
            SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
            FROM products p
            LEFT JOIN product_images pi ON p.pk = pi.product_id
            LEFT JOIN product_features pf ON p.pk = pf.product_id
            LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
            WHERE p.pk > 0;
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            # Prepare the list of products for JSON response
            product_list = {}
            for row in rows:
                pk = row[0]

                if pk not in product_list:
                    product_list[pk] = cls.buildProductDetails(row)
                else:
                    if row[8] and row[9]:  # If there's a feature
                        product_list[pk]["attributes"][row[8]] = {
                            "label": row[9],
                            "value": row[10],
                        }
                    if row[11]:  # If there's an additional image URL
                        product_list[pk]["images"].append(
                            {"url": row[11], "alt_text": row[12]}
                        )

            token_refresh_response = TokensHandler.refreshTokensIfNeeded(request)

            # Merge product data into the token refresh response
            token_refresh_response.data = jsonify(list(product_list.values())).data

            return token_refresh_response

        except Exception as e:
            print(f"Something went wrong: {e}")
            return jsonify({"error": f"Something went wrong: {e}"}), 500
        finally:
            if cursor:
                cursor.close()

    @classmethod
    def getProductByPkOrName(cls, pk, request):
        cursor = None
        try:
            connection = AppHandler.connection
            if connection is None:
                raise Exception(
                    "ProductsHandler :: getProductByPkOrName :: connection is None"
                )
            cursor = connection.cursor()

            # Modified query to also fetch product features
            query = """
            SELECT p.pk, p.name, p.description, p.short_description, p.price, p.retail_price, p.currency_type, p.in_stock, fi.feature_name, fi.feature_label, pf.value, pi.image_url, pi.alt_text
            FROM products p
            LEFT JOIN product_images pi ON p.pk = pi.product_id
            LEFT JOIN product_features pf ON p.pk = pf.product_id
            LEFT JOIN product_feature_info fi ON pf.feature_id = fi.feature_id
            WHERE p.pk = %s OR p.name = %s
            """
            cursor.execute(query, (pk, pk))
            rows = cursor.fetchall()

            if not rows:
                return jsonify({"error": "Product not found"}), 404

            # Prepare the product details for JSON response
            product_details = cls.buildProductDetails(rows[0])
            for row in rows[1:]:
                if row[8] and row[9]:  # If there's a feature
                    product_details["attributes"][row[8]] = {
                        "label": row[9],
                        "value": row[10],
                    }
                if row[11]:  # If there's an additional image URL
                    product_details["images"].append(
                        {"url": row[11], "alt_text": row[12]}
                    )

            token_refresh_response = TokensHandler.refreshTokensIfNeeded(request)

            # Merge product data into the token refresh response
            token_refresh_response.data = jsonify(product_details).data

            return token_refresh_response
        except Exception as e:
            print(f"Something went wrong: {e}")
            return jsonify({"error": f"Something went wrong: {e}"}), 500
        finally:
            if cursor:
                cursor.close()

    @classmethod
    def buildProductDetails(cls, row):
        if row is None or len(row) < 13:
            return {
                "pk": "",
                "name": "",
                "description": "",
                "short_description": "",
                "price": "",
                "retail_price": "",
                "currency_type": "",
                "currency_symbol": "",
                "in_stock": False,
                "attributes": {},
                "images": [],
            }

        product_details = {
            "pk": row[0],
            "name": row[1],
            "description": row[2],
            "short_description": row[3],
            "price": str(row[4]),  # Convert Decimal to string
            "retail_price": str(row[5]),
            "currency_type": row[6],
            "currency_symbol": AppHandler.CURRENCY_SYMBOLS.get(row[6], ""),
            "in_stock": row[7],
            "attributes": {},
            "images": [],
        }

        if (
            row[8] is not None and row[9] is not None and row[10] is not None
        ):  # If there's a feature
            product_details["attributes"][row[8]] = {"label": row[9], "value": row[10]}

        if len(row) > 11 and row[11] is not None:  # If there's an image URL
            product_details["images"].append({"url": row[11], "alt_text": row[12]})

        return product_details

    @classmethod
    def getProductName(cls, id):
        connection = AppHandler.connection
        try:
            if connection is None:
                raise Exception(
                    "ProductsHandler :: getProductName :: connection is None"
                )
            with connection.cursor(dictionary=True) as cursor:
                query = """
                    SELECT name
                    FROM products
                    WHERE pk = %s;
                """
                cursor.execute(query, (id,))
                result = cursor.fetchone()
                return result["name"]
        except Exception as e:
            print(f"Error: {e}")
            return None
