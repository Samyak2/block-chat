"""Backends for storing blockchain
Current plan:
    1. In-memory, using lists
    2. Firebase firestore
"""

import abc
import logging
from collections import OrderedDict
from typing import List, Dict, Set
import uuid

from google.cloud import firestore
import firebase_admin as firebase
import firebase_admin.db as firebase_db

from blockchat.types.transaction import Transaction

class BlockchatStorage(abc.ABC):
    """Base class for classes that define storage of a blockchain"""
    @abc.abstractmethod
    def __init__(self):
        pass

    @abc.abstractmethod
    def genesis_present(self):
        """Returns true if gensis block is present"""
        raise NotImplementedError

    @abc.abstractmethod
    def add_node(self, address: str):
        """Adds a new peer node to the set of peer nodes.

        :param address:
        :type address: str
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def nodes(self):
        """Returns set of all peer nodes."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def chain(self):
        """Returns the entire blockchain."""
        raise NotImplementedError

    @abc.abstractmethod
    def add_block(self, block: dict):
        """Adds a new block (no verification is done) to the chain.

        :param block:
        :type block: dict
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def last_block(self):
        """Returns the last block in the chain."""
        raise NotImplementedError

    @abc.abstractmethod
    def pop_transactions(self) -> List[Transaction]:
        """Removes and returns all unconfirmed transactions."""
        raise NotImplementedError

    @abc.abstractmethod
    def append_transactions(self, transactions):
        """Adds a list of unconfirmed transactions

        :param transactions: transactions to add
        :type transactions: List of :class:`~blockchat.type.transaction.Transaction`
            objects

        :return: A list of tags that can be used to check if the transactions are still
            unconfirmed using
            :func:`~blockchat.utils.storage.BlockchatStorage.is_transaction_unconfirmed`
        :rtype: list of str
        """
        raise NotImplementedError

    @staticmethod
    def serialise_transactions(block: dict):
        """Convert all Transactions of the block to dicts"""
        block["transactions"] = list(map(lambda x: x.to_dict(), block["transactions"]))
        return block

    @staticmethod
    def deserialise_transactions(block: dict):
        """Convert all transaction dicts in the block to Transaction objects"""
        block["transactions"] = list(map(lambda x: Transaction(**x), block["transactions"]))
        return block

    @abc.abstractmethod
    def is_transaction_unconfirmed(self, tag):
        """Returns True if transaction is in unconfirmed transactions.
        Note: Does not say anything about the transaction being confirmed.

        :param tag: A transaction tag returned by
            :func:`~blockchat.utils.storage.BlockchatStorage.append_transactions`
        :type tag: str

        :return: boolean indicating whether transaction is unconfirmed or not
        :rtype: bool
        """
        return NotImplementedError

    @abc.abstractmethod
    def is_transaction_confirmed(self, tag):
        """Returns True if transaction is in a mined block.
        Note: Use :func:`~blockchat.utils.storage.BlockchatStorage.is_transaction_unconfirmed`
            if the transaction was newly added, use this function only after that one
            returns False.

        :param tag: A transaction tag returned by
            :func:`~blockchat.utils.storage.BlockchatStorage.append_transactions`
        :type tag: str

        :return: boolean indicating whether transaction is confirmed or not
        :rtype: bool
        """
        return NotImplementedError

    @abc.abstractmethod
    def num_transactions(self):
        """Returns the number of unconfirmed transactions

        :rtype: integer
        """
        return NotImplementedError

    @abc.abstractmethod
    def get_user_messages(self, user_key):
        """Returns all the transactions (mined + unconfirmed) which involve the user
            given by user_key.

        :param user_key: the user's public key
        :type user_key: str

        :return: list of :class:`~blockchat.type.transaction.Transaction` objects
        """
        return NotImplementedError

class FirebaseBlockchatStorage(BlockchatStorage):
    """Blockchain storage provider with Firebase firestore and realtime database"""
    def __init__(self):
        self.db = firestore.Client.from_service_account_json("./firebase-adminsdk.json")
        self.con_ref = self.db.collection("blockchain")
        self.node_ref = self.db.collection("nodes")
        logging.info("Firestore connected")

        firebase.initialize_app(firebase.credentials.Certificate("./firebase-adminsdk.json"), {
            "databaseURL": "https://blockchat-node-01.firebaseio.com/",
            "databaseAuthVariableOverride": {
                "uid": "blockchat"
            }
        })
        self.tx_ref = firebase_db.reference("/transactions")
        super().__init__()

    def genesis_present(self):
        try:
            stream = self.con_ref.where("index", "==", 1).limit(1).stream()
            next(stream)
        except StopIteration:
            logging.warning("Genesis block does not exist on database. Creating...")
            return False
        return True

    def add_node(self, address):
        new_node_doc_ref = self.node_ref.document()
        new_node_doc_ref.set({"node_addr": address})

    @property
    def nodes(self):
        nodes = set()
        for node_doc_ref in self.node_ref.list_documents():
            node_doc = node_doc_ref.get().to_dict()
            nodes.add(node_doc["node_addr"])
        return nodes

    @property
    def chain(self):
        stream = self.con_ref.order_by("index", direction="ASCENDING").stream()
        chain = [dr.to_dict() for dr in stream]
        chain = [self.deserialise_transactions(block) for block in chain]
        return chain

    def add_block(self, block: dict):
        self.serialise_transactions(block)
        self.con_ref.document(str(block["index"])).set(block)

    @property
    def last_block(self):
        stream = self.con_ref.order_by("index", direction="DESCENDING").limit(1).stream()
        block = next(stream).to_dict()
        self.deserialise_transactions(block)
        return block

    def pop_transactions(self) -> List[Transaction]:
        txs = self.tx_ref.get()
        transactions = []
        for key, value in txs.items():
            self.tx_ref.child(key).delete()
            transactions.append(Transaction(**value))
        return transactions

    def append_transactions(self, transactions: List[Transaction]):
        etags = []
        for transaction in transactions:
            ref = self.tx_ref.push(transaction.to_dict())
            _, etag = ref.get(etag=True)
            etags.append(f"{ref.key}:::{etag}")
        return etags

    def is_transaction_unconfirmed(self, tag: str):
        key, etag = tag.split(":::")
        changed, _, _ = self.tx_ref.child(key).get_if_changed(etag=etag)
        return not changed

    def num_transactions(self):
        tx_keys = self.tx_ref.get(shallow=True)
        return len(tx_keys)

class InMemoryBlockchatStorage(BlockchatStorage):
    """Blockchain storage provider which stores the chain and transactions in memory (as lists)"""
    def __init__(self):
        self.current_chain: List[Dict] = []
        self.transactions: OrderedDict = OrderedDict()
        self.nodes_set: Set[str] = set()
        super().__init__()

    def add_node(self, address):
        self.nodes_set.add(address)

    def genesis_present(self):
        return len(self.current_chain) > 0

    @property
    def nodes(self):
        return list(self.nodes_set)

    @property
    def chain(self):
        return self.current_chain

    def add_block(self, block: dict):
        self.current_chain.append(block)

    @property
    def last_block(self):
        return self.current_chain[-1]

    def pop_transactions(self) -> List[Transaction]:
        transactions = []
        try:
            while True:
                _, transaction = self.transactions.popitem(last=False)
                transactions.append(transaction)
        except KeyError:
            pass
        return transactions

    def append_transactions(self, transactions: List[Transaction]):
        tags = []
        for transaction in transactions:
            tag = str(uuid.uuid4())
            tags.append(tag)
            self.transactions[tag] = transaction
        return tags

    def is_transaction_unconfirmed(self, tag):
        return tag in self.transactions

    def is_transaction_confirmed(self, tag):
        for block in reversed(self.current_chain):
            for transaction in block["transactions"]:
                if transaction.tag == tag:
                    return True
        return False

    def num_transactions(self):
        return len(self.transactions)

    def get_user_messages(self, user_key):
        txs = []
        for block in self.current_chain:
            for transaction in block["transactions"]:
                if user_key in (transaction.sender, transaction.receiver):
                    tx = transaction.to_dict()
                    tx["status"] = "mined"
                    txs.append(tx)
        for transaction in self.transactions:
            if user_key in (transaction.sender, transaction.receiver):
                tx = transaction.to_dict()
                tx["status"] = "unc"
                txs.append(tx)
                txs.append(transaction)
        return txs
