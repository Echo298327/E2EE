"""
This file contains the ClientDetails class which is used to store the details of the client.
"""


class ClientDetails:
    def __init__(self, user_id: str):
        self.id = user_id
        self.public_key = None
        self.private_key = None

    def set_public_key(self, public_key):
        self.public_key = public_key

    def set_private_key(self, private_key):
        self.private_key = private_key
