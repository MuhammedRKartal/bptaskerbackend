import hashlib
import os

import qrcode
import requests
from dotenv import load_dotenv

load_dotenv()


class UtilsHandler:

    @classmethod
    def createQrCode(cls, data, invoice_id):
        # Define the directory where the QR code images will be saved
        directory = "../static/qrcodes"

        # Check if the directory exists, and create it if it does not
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Setup QR code generation
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)

        # Generate QR code image
        img = qr.make_image(fill_color="black", back_color="white")

        # Define the file path for saving the QR code image
        file_path = os.path.join(directory, f"{invoice_id}.png")

        # Save the QR image as a file
        img.save(file_path)
        print(f"QR Code saved to {file_path}")

    @classmethod
    def createRocketchatUser(cls, username, email, password):
        url = "https://chat.wowtasker.io/api/v1/users.create"
        headers = {
            "X-Auth-Token": os.getenv("RC_AUTH_TOKEN"),
            "X-User-Id": os.getenv("RC_USER_ID"),
            "Content-type": "application/json",
        }
        data = {
            "username": username,
            "email": email,
            "password": password,
            "name": username,
        }
        response = requests.post(url, json=data, headers=headers)
        return response.json()

    @classmethod
    def fileHash(cls, filepath, hash_func="sha256"):
        """
        Generate a hash for a file.

        :param filepath: Path to the file to hash
        :param hash_func: Name of the hash function to use (e.g., 'sha256', 'md5')
        :return: The hexadecimal hash string of the file
        """
        # Create a hash object
        h = hashlib.new(hash_func)
        # Open the file in binary mode and update the hash object with chunks
        with open(filepath, "rb") as file:
            while chunk := file.read(8192):
                h.update(chunk)
        # Return the hexadecimal digest of the hash
        return h.hexdigest()
