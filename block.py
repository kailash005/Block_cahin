import time
from collections import OrderedDict
from hashlib import sha512
import json


class Block:

    def __init__(self, index, transactions, nonce, previous_hash, timestamp=time.time()):
        self.index = index  # Block Identification
        self.timestamp = timestamp  # Time created
        self.transactions = transactions  # Block's Transactions
        self.nonce = nonce  # Proof of work
        self.previous_hash = previous_hash  # Connecting hash to previous block

        # After successful hashing this should be filled out
        self.current_hash = None  # Current hash

    def to_od(self):
        od = OrderedDict([
            ('index', self.index),
            ('timestamp', self.timestamp),
            ('transactions', ([self.trans_to_od(trans) for trans in self.transactions])),
            ('nonce', self.nonce),
            ('previous_hash', self.previous_hash)
        ])

        return od
        
    def trans_to_od(self, trans):
        try:
            to_od= OrderedDict([
            ('sender_address', trans["sender_address"]),
            ('receiver_address', trans["receiver_address"]),
            ('amount', trans["amount"]),
            ('transaction_id', trans["transaction_id"]),
            ('transaction_inputs', trans["transaction_inputs"]),
            ('transaction_outputs', trans["transaction_outputs"]),
            ("signature",trans["signature"]),
            ("change",trans["change"])])
        except:
            to_od = trans.to_od()
        return to_od
    

    def to_json(self):
        return json.dumps(self.to_od(), default=str)

    def get_hash(self):
        return self.get_hash_obj().hexdigest()

    def get_hash_obj(self):
        return sha512(str(self.to_json()).encode('utf-8'))
