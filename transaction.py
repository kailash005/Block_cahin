import json
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from models import db, User
from collections import OrderedDict
from hashlib import sha512
import base64


class Transaction:

    _id = 0     # Incremental id for each instance created

    def __init__(self, sender_address, receiver_address, amount, transaction_inputs, ids, genesis=False):

        self.sender_address = sender_address  # Sender's public key
        self.receiver_address = receiver_address  # Receiver's public key
        self.amount = amount  # Transfer Amount
        self.transaction_id = str(ids)+str(Transaction._id)  # Transaction Id
        self.transaction_inputs = transaction_inputs  # Previous Transaction Id
        self.transaction_outputs = []  # {id: (Receiver/Sender Address, Amount/Change)}
        self.signature = ''  # Proof that sender requested transaction
        self.change = 0
        self.user_id = ids

        if not genesis:
            total_utxo = int(User.query.filter_by(id=ids).first().total_htbc)
            self.change = total_utxo - self.amount
            if self.change < 0: 
                self.change = 0
            else:
                self.change = -self.amount
            self.transaction_outputs.append(
                {str(self.user_id) + str(Transaction._id): (self.receiver_address, self.amount)})
            Transaction._id += 1
            self.transaction_outputs.append(
                {str(self.user_id) + str(Transaction._id): (self.sender_address, self.change)})

        else:
            self.transaction_outputs.append({"0"+str(Transaction._id): (self.receiver_address, self.amount)})
        Transaction._id += 1

    def to_od(self):
        # Convert object to ordered dictionary (so it produces same results every time)
        od = OrderedDict([
            ('sender_address', self.sender_address),
            ('receiver_address', self.receiver_address),
            ('amount', self.amount),
            ('transaction_id', self.transaction_id),
            ('transaction_inputs', self.transaction_inputs),
            ('transaction_outputs', self.transaction_outputs),
            ('signature', self.signature),
            ('change', self.change),
            ('user_id', self.user_id)
        ])

        return od

    def to_json(self):
        return json.dumps(self.to_od(), default=str)


    def get_hash(self):
        return self.get_hash_obj().hexdigest()

    def get_hash_obj(self):
        return sha512(str(self.to_json()).encode('utf-8'))

    def sign_transaction(self, private_key):
        priv_key = RSA.importKey(private_key)
        my_sign = PKCS1_v1_5.new(priv_key)
        transaction = self.to_od()
        h = SHA.new(json.dumps(transaction, default=str).encode('utf8'))
        self.signature = base64.b64encode(my_sign.sign(h)).decode('utf8')
