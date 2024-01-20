import time
import json
import hashlib
import uuid
from datetime import datetime

#base of chain is based on https://medium.com/@vanflymen/learn-blockchains-by-building-one-117428612f46
#@ray.remote
class Channel(object):
    def __init__(self, id):
        self.id = id
        self.chain = []
        self.current_transaction = []
        self.endorsing_peers = []

    def set_endorsing_peers(self, endorsing_peers):
        self.endorsing_peers = endorsing_peers
        self.set_endorsment_policy()

    def set_organizations(self, organizations):
        self.organizations = organizations

    def set_endorsment_policy(self):
        self.endorsment_policy = {
            "number_of_endorsing_peers": 1,
            "endorsing_peers": self.endorsing_peers.keys()
        }
    
    #TODO check how a block is build in Hyperledger, especially with regard to the hash
    def new_block(self):
        previous_block = self.last_block()
        previous_hash = None

        if previous_block is not None:
            previous_hash = self.hash(previous_block['blockheader'])

        blockheader = {
            'index': len(self.chain) + 1,
            'current_hash': self.hash(self.current_transaction),
            'previous_hash': previous_hash,
        }

        block = {
            'blockheader': blockheader,
            'transactions': self.current_transaction,
        }

        self.current_transaction = []

        self.chain.append(block)

    def new_access_transaction(self, resource_id, recipient, decision, signature):
        now = datetime.now()
        date_time = now.strftime("%d/%m/%Y %H:%M:%S")
        self.current_transaction.append({
            'resource_id': str(resource_id),
            'recipient': recipient,
            'timestamp': date_time,
            'access_decision': decision,
            'owner_signature': signature,
            'type': 'access'
        })

        print("current transaction: ", self.current_transaction)

        self.new_block()

    def new_storage_transactions(self, resource_id, ownerlist, owner_key):
        self.current_transaction.append({
            'resource_id': str(resource_id),
            'ownerlist': ownerlist,
            'signature_pk': owner_key,
            'type': 'storage'
        })

        self.new_block()

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
        
    def last_block(self):
        if not self.chain:
            return None
        else:
            return self.chain[-1]

    def get_chain(self):
        return self.chain