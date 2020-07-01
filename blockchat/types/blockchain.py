import logging
from typing import List

import hashlib
import json
from time import time
from urllib.parse import urlparse

from flask.json import JSONEncoder, JSONDecoder
import nacl.signing
import requests

import blockchat.utils.encryption as encryption
import blockchat.utils.storage as storage
from blockchat.types.transaction import Transaction

# custom JSONEncoder for our custom classes
class BlockchatJSONEncoder(JSONEncoder):
    """Custom JSON encoder to encode Transactions correctly"""
    def default(self, o):
        if isinstance(o, Transaction):
            return o.to_dict()
        return super(BlockchatJSONEncoder, self).default(o)
class BlockchatJSONDecoder(JSONDecoder):
    """Custom JSON decoder to decode Transactions correctly"""
    def __init__(self, *args, **kwargs):
        self.orig_obj_hook = kwargs.pop("object_hook", None)
        super(BlockchatJSONDecoder, self).__init__(
            *args,
            object_hook=self.custom_obj_hook, **kwargs)

    def custom_obj_hook(self, dct):
        """Custom decode function for Transaction"""
        # Calling custom decode function:
        if "sender" in dct and "receiver" in dct and "sender" in dct and "signature" in dct:
            dct = Transaction(dct["sender"], dct["receiver"], dct["message"], dct["signature"])
        if self.orig_obj_hook:  # Do we have another hook to call?
            return self.orig_obj_hook(dct)  # Yes: then do it
        return dct  # No: just return the decoded dict

class Blockchain:
    """Represents the entire blockchain present in a node"""
    def __init__(self, db: storage.BlockchatStorage,
                 node_url: str,
                 node_secret: nacl.signing.SigningKey):
        self.db = db
        self.node_url = node_url
        self.node_secret = node_secret
        if not db.genesis_present():
            # Create the genesis block
            self.new_block(previous_hash='1', proof=100, transactions=[],
                           last_block={"index": 0}, verify=False)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = parse_node_addr(address)
        self.db.add_node(parsed_url)

    def get_nodes(self):
        """Returns a set of all registered node"""
        return self.db.nodes

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

    def replace_chain(self, chain: List):
        """Replaces the blockchain with the longer (valid) "chain"
        Note that validity isn't checked here

        Arguments:
        chain: chain to replace with
        """
        leftout_txs = []
        i = 1
        current_chain = self.db.chain
        min_len = len(current_chain)
        while i < min_len:
            if self.hash(current_chain[i]) != self.hash(chain[i]):
                leftout_txs.extend(current_chain[i]["transactions"])
            i += 1
        other_len = len(chain)
        while i < other_len:
            self.add_block(chain[i])
            i += 1
        self.db.append_transactions(leftout_txs)
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
            'source_node': self.node_url
        }

        if verify:
            self.add_block(block)
            self.publish_block(block)
        else:
            self.db.add_block(block)
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
                    logging.warning("Could not publish block to node %s", node)


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

        self.db.add_block(block)
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
        if signature is None and self_sign is True:
            message, signature = encryption.sign_message(self.node_secret, repr(transaction))
            transaction.signature = signature
        if not transaction.verify_transaction():
            return False

        if add_to is None:
            self.db.append_transactions([transaction])
        else:
            add_to.append(transaction)

        return True

    @property
    def last_block(self):
        """The last added block in the chain"""
        return self.db.last_block

    def __len__(self):
        return self.last_block["index"]

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
