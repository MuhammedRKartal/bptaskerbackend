import mariadb

from .AppHandler import AppHandler
from .EmailHandler import EmailHandler
from .ProductsHandler import ProductsHandler
from .SessionsHandler import SessionsHandler


class LicensesHandler:

    @classmethod
    def getAvailableUnlockerLicenses(cls, user_id):
        connection = AppHandler.connection
        try:
            if connection is None:
                raise Exception(
                    "LicensesHandler :: get_available_unlocker_licenses :: connection is None"
                )
            # clean up old sessions, then check for available licenses
            SessionsHandler.cleanupOldSessions(connection)
        except Exception as e:
            print(f"Error: {e}")
            return []

        try:
            with connection.cursor(dictionary=True) as cursor:
                query = """
                    SELECT ul.unlocker_license
                    FROM unlocker_licenses ul
                    LEFT JOIN unlocker_sessions us ON ul.unlocker_license = us.unlocker_license_id
                    WHERE us.unlocker_license_id IS NULL AND ul.user_id = %s;
                """
                cursor.execute(query, (user_id,))
                result = cursor.fetchall()
                # Extracting unlocker_license values into a list
                available_licenses = [row["unlocker_license"] for row in result]
                return available_licenses
        except Exception as e:
            print(f"Error: {e}")
            return []

    @classmethod
    def allocateLicense(cls, user_id, product, amount):
        connection = AppHandler.connection
        if connection is None:
            return False, 0
        cursor = connection.cursor()
        # First, check if the user exists
        user_exists_query = (
            "SELECT user_id, username, email FROM users WHERE user_id = %s;"
        )
        cursor.execute(user_exists_query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            return False, 0

        # If the user exists, proceed to allocate the unlocker licenses
        select_query = "SELECT unlocker_license FROM unused_unlocker_licenses LIMIT %s;"
        cursor.execute(select_query, (amount,))
        licenses = cursor.fetchall()
        if len(licenses) < amount:
            cursor.close()
            EmailHandler.__sendemail(
                "earshelh@gmail.com",
                "Licence allocation failure!",
                f"User {user_id} paid for {ProductsHandler.getProductName(product)} but could not allocate the requested number of licenses. Allocated 0 out of {amount}.",
            )
            return False, len(licenses)

        insert_query = "INSERT INTO unlocker_licenses (user_id, user_name, email, unlocker_license, enabled) VALUES (%s, %s, %s, %s, %s);"
        delete_query = (
            "DELETE FROM unused_unlocker_licenses WHERE unlocker_license = %s;"
        )
        num_rows_affected = 0
        try:
            for license in licenses:
                cursor.execute(insert_query, (user[0], user[1], user[2], license[0], 1))
                cursor.execute(delete_query, (license[0],))
            connection.commit()
            num_rows_affected = cursor.rowcount

            if num_rows_affected < amount:
                EmailHandler.__sendemail(
                    "earshelh@gmail.com",
                    "Licence allocation failure!",
                    f"User {user_id} paid for {product} but could not allocate the requested number of licenses. Allocated {num_rows_affected} out of {amount}.",
                )
                raise mariadb.Error(
                    f"Could not allocate the requested number of licenses. Allocated {num_rows_affected} out of {amount}."
                )

        except mariadb.IntegrityError:
            # This block catches an IntegrityError, which includes violations of UNIQUE constraints
            return False, num_rows_affected
        except mariadb.Error as err:
            # Handle other potential errors
            print("Error: ", err)
            return False, num_rows_affected
        finally:
            cursor.close()
        EmailHandler.__sendemail(
            "earshelh@gmail.com",
            "Order success!",
            f"User {user_id} paid for {product}. Allocated {num_rows_affected} out of {amount}.",
        )
        return True, num_rows_affected
