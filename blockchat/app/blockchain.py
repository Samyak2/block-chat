import os
import logging
import atexit

import nacl
from flask import Flask, jsonify, request
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler

from blockchat.utils import encryption
from blockchat.types.blockchain import Blockchain, BlockchatJSONEncoder, BlockchatJSONDecoder
from blockchat.types.blockchain import parse_node_addr
import blockchat.utils.storage as storage

numeric_level = getattr(logging, os.getenv("LOG_LEVEL", "WARNING"), "WARNING")
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

storage_backend = os.getenv("STORAGE_TYPE", "memory").lower()
if storage_backend == "firebase":
    db = storage.FirebaseBlockchatStorage()
    logging.warning("Using Firebase storage backend")
else:
    db = storage.InMemoryBlockchatStorage()
    logging.warning("Using in-memory storage backend")

# Instantiate the Blockchain
blockchain = Blockchain(db, node_url, node_secret)

def mine_wrapper():
    if blockchain.db.num_transactions() == 0:
        return False
    logging.info("Mining now")
    # ensure chain is the best before mining
    blockchain.resolve_conflicts()

    last_block = blockchain.last_block
    # get the transactions to be added
    transactions = blockchain.db.pop_transactions()
    # add a "mine" transaction
    blockchain.new_transaction(node_identifier, node_identifier, "<<MINE>>",
                               self_sign=True, add_to=transactions)

    # We run the proof of work algorithm to get the next proof...
    proof = blockchain.proof_of_work(last_block, transactions)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash, transactions, last_block)

    return block

@app.route('/mine', methods=['GET'])
def mine():
    block = mine_wrapper()
    if not block:
        return "Nothing to mine", 200

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
    tag = blockchain.new_transaction(values['sender'], values['recipient'],
                                     values['message'], values['signature'])
    if not tag:
        return "Cannot verify transaction", 400

    response = {'message': 'Transaction will be added to the next block.',
                'tag': tag}
    return jsonify(response), 201

@app.route('/transactions/is_unconfirmed', methods=['GET'])
def check_transaction_unconfirmed():
    if 'tag' not in request.args:
        return 'Missing tag in parameters', 400
    tag = request.args.get('tag')
    unconfirmed = blockchain.db.is_transaction_unconfirmed(tag)
    return jsonify({"unconfirmed": unconfirmed}), 201

@app.route('/transactions/is_confirmed', methods=['GET'])
def check_transaction_confirmed():
    if 'tag' not in request.args:
        return 'Missing tag in parameters', 400
    tag = request.args.get('tag')
    confirmed = blockchain.db.is_transaction_confirmed(tag)
    return jsonify({"confirmed": confirmed}), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    chain = blockchain.db.chain
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

# schedule mine job every x minutes
sched = BackgroundScheduler(daemon=True)
sched.add_job(mine_wrapper, 'interval', minutes=1)
sched.start()

# shutdown scheduler when exiting
atexit.register(lambda: sched.shutdown(wait=False))

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, threaded=False, processes=1)
