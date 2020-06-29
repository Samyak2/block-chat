import os
import sys
import hashlib
import json
from time import time
from urllib.parse import urlparse
from typing import List
import copy
import logging

import nacl
import requests
from flask import Flask, jsonify, request
from flask.json import JSONEncoder, JSONDecoder
from google.cloud import firestore
import firebase_admin as firebase
import firebase_admin.db as firebase_db

import encryption

numeric_level = getattr(logging, os.getenv("LOG_LEVEL"), "WARNING")
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % os.getenv("LOG_LEVEL"))
logging.basicConfig(level=numeric_level)

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
            return False
        try:
            sender_key = encryption.decode_verify_key(self.sender)
            encryption.decode_verify_key(self.receiver)
        except (ValueError, TypeError) as e:
            logging.error(f"Error while verifying transaction: {e}")
            return False
        return encryption.verify_message(sender_key,
                                         bytes(repr(self), 'utf-8'),
                                         self.signature)

class Blockchain:
    """Represents the entire blockchain present in a node"""
    def __init__(self, con_ref: firestore.CollectionReference,
                 node_ref: firestore.CollectionReference,
                 tx_ref: firebase_db.Reference):
        self.node_ref = node_ref
        self.con_ref = con_ref
        self.tx_ref = tx_ref
        try:
            stream = con_ref.where("index", "==", 1).limit(1).stream()
            next(stream)
        except StopIteration:
            logging.warning("Genesis block does not exist on database. Creating...")

            # Create the genesis block
            self.new_block(previous_hash='1', proof=100, transactions=[],
                           last_block={"index": 0}, verify=False)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = parse_node_addr(address)
        new_node_doc_ref = self.node_ref.document()
        new_node_doc_ref.set({"node_addr": parsed_url})

    def get_nodes(self):
        """Returns a set of all registered node"""
        nodes = set()
        for node_doc_ref in self.node_ref.list_documents():
            node_doc = node_doc_ref.get().to_dict()
            nodes.add(node_doc["node_addr"])
        return nodes

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            logging.info('%s', last_block)
            logging.info('%s', block)
            logging.info("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                logging.warning("Invalid block hash at index %s", current_index)
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], last_block_hash, block['proof'],
                                    block["transactions"]):
                logging.warning("Invalid proof of work at index %s", current_index)
                return False
            for transaction in block["transactions"]:
                if not transaction.verify_transaction():
                    logging.warning("Invalid transaction at index %s", current_index)
                    return False

            last_block = block
            current_index += 1

        return True

    @property
    def current_chain(self):
        """Returns a list of the current blockchain"""
        stream = self.con_ref.order_by("index", direction="ASCENDING").stream()
        chain = [dr.to_dict() for dr in stream]
        chain = [self.deserialise_transactions(block) for block in chain]
        return chain

    def replace_chain(self, chain: List):
        """Replaces the blockchain with the longer (valid) "chain"
        Note that validity isn't checked here

        Arguments:
        chain: chain to replace with
        """
        leftout_txs = []
        i = 1
        current_chain = self.current_chain
        min_len = len(current_chain)
        while i < min_len:
            if self.hash(current_chain[i]) != self.hash(chain[i]):
                leftout_txs.extend(current_chain[i]["transactions"])
            i += 1
        other_len = len(chain)
        while i < other_len:
            self.add_block(chain[i])
            i += 1
        self.append_transactions(leftout_txs)
        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.get_nodes()
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain_length')

            if response.status_code == 200:
                length = response.json()['length']
                # check if length is longer
                if length > max_length:
                    chain_response = requests.get(f'http://{node}/chain')
                    if chain_response.status_code == 200:
                        chain = chain_response.json(cls=BlockchatJSONDecoder)['chain']
                        # Check if the chain is valid
                        if self.valid_chain(chain):
                            max_length = length
                            new_chain = chain
                        else:
                            logging.error("Invalid chain on node %s", node)

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.replace_chain(new_chain)
            return True

        return False

    def new_block(self, proof, previous_hash, transactions, last_block, verify=True):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': last_block["index"] + 1,
            'timestamp': time(),
            'transactions': transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(last_block),
            'source_node': node_url
        }

        if verify:
            self.add_block(block)
            self.publish_block(block)
        else:
            self.serialise_transactions(block)
            self.con_ref.document(str(block["index"])).set(block)
        return block

    def publish_block(self, block):
        """Publishes block to all nodes"""
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        for node in self.get_nodes():
            if node != block["source_node"]:
                response = requests.post(f'http://{node}/add_block',
                                         data=json.dumps({"block": block},
                                                         cls=BlockchatJSONEncoder),
                                         headers=headers)
                if not response.ok:
                    logging.warning(f"Could not publish block to node {node}")


    def add_block(self, block):
        """
        Add an already mined block to the chain

        :param block: The block to be added
        """
        last_block = self.last_block
        last_hash = self.hash(last_block)
        last_proof = last_block["proof"]

        # check if previous hash matches last block on our chain
        if last_hash != block["previous_hash"]:
            return False
        # check if proof is correct
        for transaction in block["transactions"]:
            if not transaction.verify_transaction():
                return False
        if not self.valid_proof(last_proof, last_hash, block["proof"], block["transactions"]):
            return False

        self.serialise_transactions(block)
        self.con_ref.document(str(block["index"])).set(block)
        return True

    def pop_transactions(self) -> List[Transaction]:
        txs = self.tx_ref.get()
        transactions = []
        for key, value in txs.items():
            self.tx_ref.child(key).delete()
            transactions.append(Transaction(**value))
        return transactions

    def append_transactions(self, transactions: List[Transaction]):
        for transaction in transactions:
            self.tx_ref.push(transaction.to_dict())

    def new_transaction(self, sender: bytes, recipient: bytes, message: str,
                        signature: bytes = None, self_sign: bool = False,
                        add_to: List = None):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        transaction = Transaction(sender, recipient, message, signature)
        if signature is None and self_sign is True:
            message, signature = encryption.sign_message(node_secret, repr(transaction))
            transaction.signature = signature
        if not transaction.verify_transaction():
            return False

        if add_to is None:
            self.append_transactions([transaction])
        else:
            add_to.append(transaction)

        return True

    @property
    def last_block(self):
        """The last added block in the chain"""
        stream = self.con_ref.order_by("index", direction="DESCENDING").limit(1).stream()
        block = next(stream).to_dict()
        self.deserialise_transactions(block)
        return block

    def __len__(self):
        return self.last_block["index"]

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

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True, cls=BlockchatJSONEncoder).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block, transactions):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, last_hash, proof, transactions) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, last_hash, proof, transactions: List[Transaction]):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        transactions_representation = "".join(map(repr, transactions))
        guess = f'{last_proof}{proof}{last_hash}{transactions_representation}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        ret = guess_hash[:4] == "0000"
        # if ret:
        #     print("Guess:", guess)
        return ret

def parse_node_addr(addr):
    """Formats the URL to have only scheme and hostname (with port)"""
    parsed_url = urlparse(addr)
    if parsed_url.scheme and parsed_url.netloc:
        return f"{parsed_url.scheme}://{parsed_url.netloc}"
    raise ValueError("Invalid URL")

# Instantiate the Node
app = Flask(__name__)

# custom JSONEncoder for our custom classes
class BlockchatJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Transaction):
            return obj.to_dict()
        return super(BlockchatJSONEncoder, self).default(obj)
class BlockchatJSONDecoder(JSONDecoder):
    def __init__(self, *args, **kwargs):
        self.orig_obj_hook = kwargs.pop("object_hook", None)
        super(BlockchatJSONDecoder, self).__init__(
            *args,
            object_hook=self.custom_obj_hook, **kwargs)

    def custom_obj_hook(self, dct):
        # Calling custom decode function:
        if "sender" in dct and "receiver" in dct and "sender" in dct and "signature" in dct:
            dct = Transaction(dct["sender"], dct["receiver"], dct["message"], dct["signature"])
        if self.orig_obj_hook:  # Do we have another hook to call?
            return self.orig_obj_hook(dct)  # Yes: then do it
        return dct  # No: just return the decoded dict
app.json_encoder = BlockchatJSONEncoder
app.json_decoder = BlockchatJSONDecoder

# load node secret and node address from env vars
node_secret = nacl.signing.SigningKey(bytes.fromhex(os.getenv("NODE_KEY")))
node_url = os.getenv("NODE_ADDR", None)
assert node_url is not None
node_url = parse_node_addr(node_url)
node_identifier = encryption.encode_verify_key(node_secret.verify_key).decode()

db = firestore.Client.from_service_account_json("./firebase-adminsdk.json")
blockchain_c = db.collection("blockchain")
node_c = db.collection("nodes")
logging.info("Firestore connected")

firebase.initialize_app(firebase.credentials.Certificate("./firebase-adminsdk.json"), {
    "databaseURL": "https://blockchat-node-01.firebaseio.com/",
    "databaseAuthVariableOverride": {
        "uid": "blockchat"
    }
})
transactions_ref = firebase_db.reference("/transactions")

# Instantiate the Blockchain
blockchain = Blockchain(blockchain_c, node_c, transactions_ref)

@app.route('/mine', methods=['GET'])
def mine():
    # ensure chain is the best before mining
    blockchain.resolve_conflicts()

    last_block = blockchain.last_block
    # get the transactions to be added
    transactions = blockchain.pop_transactions()
    # add a "mine" transaction
    blockchain.new_transaction(node_identifier, node_identifier, "<<MINE>>",
                               self_sign=True, add_to=transactions)

    # We run the proof of work algorithm to get the next proof...
    proof = blockchain.proof_of_work(last_block, transactions)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash, transactions, last_block)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'message', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'],
                                       values['message'], values['signature'])
    if not index:
        return "Cannot verify transaction", 400

    response = {'message': f'Transaction will be added to the next block.'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    chain = blockchain.current_chain
    response = {
        'chain': chain,
        'length': chain[-1]["index"]
    }
    return jsonify(response), 200

@app.route('/chain_length', methods=['GET'])
def chain_length():
    response = {
        'length': len(blockchain),
    }
    return jsonify(response), 200

@app.route('/add_block', methods=['POST'])
def add_block():
    values = request.get_json()
    block_to_add = values.get('block')

    # try to add block
    success = blockchain.add_block(block_to_add)

    if success:
        return jsonify({
            "message": "Block added successfully"}), 200
    return "Error: Invalid block", 400

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    replaced = blockchain.resolve_conflicts()

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.get_nodes()),
        'chain_replaced': replaced
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced'
        }
    else:
        response = {
            'message': 'Our chain is authoritative'
        }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, threaded=False, processes=1)
