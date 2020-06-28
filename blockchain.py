import os
import sys
import hashlib
import json
from time import time
from urllib.parse import urlparse
from typing import List
import copy

import nacl
import requests
from flask import Flask, jsonify, request
from flask.json import JSONEncoder, JSONDecoder

import encryption

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
            print("Error while verifying transaction:", e)
            return False
        return encryption.verify_message(sender_key,
                                         bytes(repr(self), 'utf-8'),
                                         self.signature)

class Blockchain:
    """Represents the entire blockchain present in a node"""
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100, transactions=[], verify=False)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


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
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                print(f"Invalid block hash at index {current_index}", file=sys.stderr)
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], last_block_hash, block['proof'],
                                    block["transactions"]):
                print(f"Invalid proof of work at index {current_index}", file=sys.stderr)
                return False
            for transaction in block["transactions"]:
                if not transaction.verify_transaction():
                    print(f"Invalid transaction at index {current_index}", file=sys.stderr)
                    return False

            last_block = block
            current_index += 1

        return True

    def replace_chain(self, chain: List):
        """Replaces the blockchain with the longer (valid) "chain"
        Note that validity isn't checked here

        Arguments:
        chain: chain to replace with
        """
        assert len(self.chain) < len(chain)
        leftout_txs = []
        min_len = len(self.chain)
        i = 1
        while i < min_len:
            if self.hash(self.chain[i]) != self.hash(chain[i]):
                leftout_txs.extend(self.chain[i]["transactions"])
            i += 1
        self.current_transactions.extend(leftout_txs)
        self.chain = chain
        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

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
                        print(chain)
                        if self.valid_chain(chain):
                            max_length = length
                            new_chain = chain
                        else:
                            print(f"Invalid chain on node {node}")

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.replace_chain(new_chain)
            return True

        return False

    def new_block(self, proof, previous_hash, transactions, verify=True):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'source_node': node_url
        }

        # Reset the current list of transactions
        self.current_transactions = []

        if verify:
            self.add_block(block)
            self.publish_block(block)
        else:
            self.chain.append(block)
        return block

    def publish_block(self, block):
        """Publishes block to all nodes"""
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        for node in self.nodes:
            if node != block["source_node"]:
                response = requests.post(f'http://{node}/add_block',
                                         data=json.dumps({"block": block},
                                                         cls=BlockchatJSONEncoder),
                                         headers=headers)
                if not response.ok:
                    print(f"Could not publish block to node {node}", file=sys.stderr)


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

        self.chain.append(block)
        return True

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
        print(transaction)
        if signature is None and self_sign is True:
            message, signature = encryption.sign_message(node_secret, repr(transaction))
            transaction.signature = signature
        if not transaction.verify_transaction():
            return False

        if add_to is None:
            add_to = self.current_transactions
        add_to.append(transaction)

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

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
        if ret:
            print("Guess:", guess)
        return ret


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

node_secret = nacl.signing.SigningKey(bytes.fromhex(os.getenv("NODE_KEY")))
node_url = os.getenv("NODE_ADDR", None)
assert node_url is not None
node_identifier = encryption.encode_verify_key(node_secret.verify_key).decode()

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # ensure chain is the best before mining
    blockchain.resolve_conflicts()

    last_block = blockchain.last_block
    # get the transactions to be added
    transactions = copy.deepcopy(blockchain.current_transactions)
    # add a "mine" transaction
    blockchain.new_transaction(node_identifier, node_identifier, "<<MINE>>",
                               self_sign=True, add_to=transactions)

    # We run the proof of work algorithm to get the next proof...
    proof = blockchain.proof_of_work(last_block, transactions)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash, transactions)

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

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/chain_length', methods=['GET'])
def chain_length():
    response = {
        'length': len(blockchain.chain),
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

    blockchain.resolve_conflicts()

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    print("Replaced:", replaced)

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, threaded=False, processes=1)
