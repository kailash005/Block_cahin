from blocks.block import Block
from blocks.transaction import Transaction
import requests
from collections import OrderedDict
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from models import db, User
from copy import deepcopy
import base64
import json


class Blockchain:
    def __init__(self, local_address):

        # Genesis block
        self.genesis = Block(index=0, previous_hash=1, transactions=[], nonce=0)
        self.bank = local_address
        # Genesis transaction
        transaction = Transaction(sender_address="0", receiver_address=local_address, amount=1000000000,
                                  transaction_inputs='', genesis=True, ids='0')

        self.genesis.transactions.append(transaction)
        self.genesis.timestamp = 0
        self.genesis.current_hash = self.genesis.get_hash()

        self.blocks = [self.genesis]  # List of added blocks (aka chain)
        for trans in self.genesis.transactions[0].transaction_outputs:
            for ids, transaction in trans.items():
                user = User.query.filter_by(public_address = transaction[0]).first()
                user.total_htbc += transaction[1]
                db.session.commit()
        self.resolve = False  # Check chain updates (bigger chain was found)

    def __str__(self):
        chain = f'{self.genesis.index} ({0})'

        # Ignore genesis
        for block in self.blocks[1:]:
            chain += f' -> {block.index} ({block.current_hash})'

        return chain

    def add_block(self, new_block):
        if self.validate_block(new_block, 1):
            self.blocks.append(new_block)
            #Get the user who spent the money
            for trans in new_block.transactions[0].transaction_outputs:
                for id, transaction in trans.items():
                    user = User.query.filter_by(public_address = transaction[0]).first()
                    user.total_htbc += transaction[1]
                    db.session.commit()
            # If the user made a payment to the bank take a note of it
            if new_block.transactions[0].receiver_address == self.bank:
                user = User.query.filter_by(public_address = new_block.transactions[0].sender_address).first()
                user.paid_htbc += new_block.transactions[0].amount
                db.session.commit()
            return self
    def mine_block(self, block, difficulty):
        # Mine the whole block until the conditions are met
        nonce = 0
        block_to_mine = block
        block_to_mine.nonce = nonce

        # Update hash
        block_hash = block_to_mine.get_hash()

        # Try new hashes until the first n characters are 0
        while block_hash[:difficulty] != '0' * difficulty:
            nonce += 1
            block_to_mine.nonce = nonce
            block_hash = block_to_mine.get_hash()

        block_to_mine.current_hash = block_hash
        self.add_block(block_to_mine)
        return


    def resolve_conflict(self, possible_chain):

        new_blocks = possible_chain
        tmp_blockchain = []
        # Parse the json block to an actual block item
        for id, block in enumerate(new_blocks["blockchain"]):
            transactions = []

            # Load transactions from the block
            for t in block["transactions"]:
                if id == 0:
                    transaction = Transaction(sender_address=t["sender_address"],
                                            receiver_address=t["receiver_address"],
                                            amount=int(t["amount"]),
                                            transaction_inputs=t["transaction_inputs"],
                                            ids=t["user_id"], genesis=True)
                else:
                    transaction = Transaction(sender_address=t["sender_address"],
                                            receiver_address=t["receiver_address"],
                                            amount=int(t["amount"]),
                                            transaction_inputs=t["transaction_inputs"],
                                            ids=t["user_id"])

                transaction.transaction_id = t["transaction_id"]
                transaction.signature = t["signature"]
                transaction.transaction_outputs = t["transaction_outputs"]
                transaction.change = int(t["change"])

                transactions.append(transaction)

            block = Block(block["index"], transactions, block["nonce"], block["previous_hash"],
                            block["timestamp"])

            block.current_hash = block.get_hash()

            tmp_blockchain.append(block)

        # If bigger chain is found, replace existing chain
        if len(tmp_blockchain) > len(self.blocks) and self.validate_chain(tmp_blockchain):
            self.blocks = tmp_blockchain

        return self

    def to_od(self):
        od = OrderedDict([
            ('blockchain', [block.to_od() for block in self.blocks])
        ])

        return od

    def to_od_with_hash(self):
        od = OrderedDict([
            ('blockchain', [(block.to_od(), block.current_hash) for block in self.blocks])
        ])

        return od

    def to_json(self):
        # Convert object to json
        return json.dumps(self.to_od(), default=str)

# ---------------------------------------------- VERIFICATION FUNCTIONS ----------------------------------------------

    def validate_block(self, block, difficulty, new_chain = False):
        # Check the proof of work
        if difficulty * "0" != block.get_hash_obj().hexdigest()[:difficulty]:
            return False
        # Validate signature
        to_test = deepcopy(block.transactions[0])
        to_test.signature = ""
        to_test = to_test.to_json()
        h = SHA.new(to_test.encode('utf8'))
        pub_key = block.transactions[0].sender_address
        public_key = RSA.importKey(pub_key)
        sign_to_test = PKCS1_v1_5.new(public_key)
        if not(sign_to_test.verify(h, base64.b64decode(block.transactions[0].signature))):
            return False
        # Validate that no money gets sents between the players
        if block.transactions[0].receiver_address == self.genesis.transactions[0].receiver_address \
        or block.transactions[0].receiver_address == block.transactions[0].sender_address:
            None
        else:
            if block.transactions[0].sender_address == self.genesis.transactions[0].receiver_address:
                None
            else:
                return False
        # Verify the amount of money, verify that the sender has enough money to send
        if new_chain == False:
            user = User.query.filter_by(public_address = block.transactions[0].sender_address).first()
            if user.total_htbc < block.transactions[0].amount:
                return False
            # Check that it sticks to the chain
            if self.blocks[-1].current_hash != block.previous_hash and block.index != 0:
                # Maybe the chain got updated, user still needs initial bonus money
                if block.transactions[0].sender_address == self.genesis.transactions[0].receiver_address:
                    block.previous_hash = self.blocks[-1].current_hash
                    self.mine_block(block, 1)
                return False
        return True

    def validate_chain(self, blockchain):
        # Loop chain to validate that hashes are connected
        money = {}
        for (index, block) in enumerate(blockchain):
            if index == 0:
                money[block.transactions[0].receiver_address] = block.transactions[0].amount
                block.current_hash = block.get_hash()
                continue
            amount = block.transactions[0].amount
            change = block.transactions[0].change
            if block.current_hash != block.get_hash():
                return False
            if block.previous_hash != blockchain[index - 1].current_hash:
                return False
            if not(self.validate_block(block, 1, new_chain=True)):
                return False
            if money[block.transactions[0].sender_address] < amount:
                return False
            money[block.transactions[0].sender_address] = money[block.transactions[0].sender_address] - amount
            try:
                money[block.transactions[0].receiver_address] += amount
            except:
                money[block.transactions[0].receiver_address] = amount
        #If we reach this part we need to update the DB with the new info
        for pub_key, htbcs in money.items():
            user = User.query.filter_by(public_address = pub_key).first()
            user.total_htbc = htbcs
            db.session.commit()
        return True
