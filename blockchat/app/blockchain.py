import os
import logging

import nacl
from flask import Flask, jsonify, request
from google.cloud import firestore
import firebase_admin as firebase
import firebase_admin.db as firebase_db
from flask_cors import CORS

from blockchat.utils import encryption
from blockchat.types.blockchain import Blockchain, BlockchatJSONEncoder, BlockchatJSONDecoder
from blockchat.types.blockchain import parse_node_addr

numeric_level = getattr(logging, os.getenv("LOG_LEVEL"), "WARNING")
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % os.getenv("LOG_LEVEL"))
logging.basicConfig(level=numeric_level)

# Instantiate the Node
app = Flask(__name__)
CORS(app)

app.json_encoder = BlockchatJSONEncoder
app.json_decoder = BlockchatJSONDecoder

# load node secret and node address from env vars
node_secret = nacl.signing.SigningKey(bytes.fromhex(os.getenv("NODE_KEY")))
node_url = os.getenv("NODE_ADDR", None)
assert node_url is not None
node_url = parse_node_addr(node_url)
node_identifier = encryption.encode_verify_key(node_secret.verify_key)

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
blockchain = Blockchain(blockchain_c, node_c, transactions_ref, node_url, node_secret)

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
