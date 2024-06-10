# user.py
class User:
    def __init__(self, user_id, username, password):
        self.user_id = user_id
        self.username = username
        self.password = password  # Note: Store hashed passwords, not plain text!

    def change_password(self, old_password, new_password):
        if self.verify_password(old_password):
            self.password = new_password  # Remember to hash the new password
            return True
        return False

    def verify_password(self, password):
        return self.password == password  # Simplified for illustration

    def delete(self):
        # Logic to delete user from database
        pass

    def login(self, password):
        return self.verify_password(password)