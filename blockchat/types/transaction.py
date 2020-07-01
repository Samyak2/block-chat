import logging
import blockchat.utils.encryption as encryption

class Transaction:
    """Wrapper class to represent a transaction

    Arguments:
    sender (bytes): sender public key
    receiver (bytes): receiver public key
    message (str): message to be sent
    """
    def __init__(self, sender: bytes, receiver: bytes, message: str, signature: str = None):
        self.sender = sender
        self.receiver = receiver
        self.message = message
        self.signature = signature
        if signature is not None:
            self.signature = bytes.fromhex(signature)

    def __repr__(self):
        return f"<{self.sender} {self.receiver} {self.message}>"

    def to_dict(self):
        """Returns a dictionary representation of the Transaction"""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "message": self.message,
            "signature": self.signature.hex()
        }

    def verify_transaction(self):
        """Returns True if the signature is valid for this Transaction, returns False otherwise.

        The message which the signature represents should be of the following form:
        <sender_public_key receiver_public_key message>
        """
        if self.signature is None:
            print("No signature")
            return False
        try:
            sender_key = encryption.decode_verify_key(self.sender)
            encryption.decode_verify_key(self.receiver)
        except (ValueError, TypeError) as e:
            logging.error("Error while verifying transaction: %s", e)
            return False
        return encryption.verify_message(sender_key,
                                         bytes(repr(self), 'utf-8'),
                                         self.signature)
