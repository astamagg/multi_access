from hashlib import sha512
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Support.PolTree import PolTree
from queue import Queue
from Support.SDK import SDK
from Support.util import hash_transcript, hash_message, Shares
import time
import random

class WorkerOperator:
    def __init__(self, id, channel, pq, key_threshold, levels_of_access):
        self.acks = 0
        self.valid_shares = []
        self.id = id
        self.operators = {}
        self.message_queue = Queue()
        self.access_leader = None
        self.encryption_leader = None
        self.SDK = SDK(channel)
        self.sig_params = None
        self.sig_pk = None
        self.STATE = "free"
        self.STATUS = "nothing"
        self.decisions = dict()
        self.pq = pq
        self.unverified_shares = []
        self.accepted = []
        self.denied = []
        self.key_threshold = key_threshold
        self.levels_of_access = levels_of_access


    def receive_message(self, message_type, sender, arguments, time):
        self.message_queue.put((message_type, sender, arguments, time))
        self.check_queue()

    def access_request(self, attribute_set, resource_id, requester_id, time):
        # TODO might need to add a response if no action is taken
        pass

    def check_queue(self):
        processed = False
        next_task = self.message_queue.get()
        message_type = next_task[0]
        if message_type == "access_request":
            processed = True
            self.access_request(next_task[2][0], next_task[2][1], next_task[2][2], next_task[3])
        if message_type == "receive_access_request":
            processed = True
            self.receive_access_request(next_task[2][0], next_task[2][1], next_task[2][2], next_task[2][3], next_task[3])
        if self.STATUS == "request":
            if message_type == "policy":
                processed = True
                self.compare_policy(next_task[1], next_task[2][0], next_task[3])
            if message_type == "policy_response":
                processed = True
                self.compare_access_ver(next_task[1], next_task[2][0], next_task[2][1], next_task[2][2], next_task[3])
            if message_type == "acks":
                print("processing ack")
                processed = True
                self.compare_ack(next_task[1], next_task[2][0])
            if message_type == "verify_decision":
                print("got into verify decision")
                processed = True
                self.ver_final_decision(next_task[1], next_task[3], next_task[2][0])
        if self.STATUS == "share_info":
            if message_type == "owner_info":
                processed = True
                self.provide_owner_info(next_task[1], next_task[2][0], next_task[3])

        if not processed:
            self.pq.check_queue()

    def receive_signing_params(self, pk, params):
        self.sig_params = params
        self.sig_pk = pk

    def set_leaders(self, access_id, encryption_id):
        self.access_leader = access_id
        self.encryption_leader = encryption_id

    #Used for benchmarking
    def set_request(self, attribute_set, owners, decision, curr_owner):
        self.attribute_set = attribute_set
        self.owners = owners
        self.decisions[curr_owner] = decision

    def receive_access_request(self, attribute_set, requester_id, resource_id, owners, time):
        curr_time = time
        self.STATUS = "request"
        self.attribute_set = attribute_set
        self.owners = owners
        for i, owner in enumerate(owners.values()):
            curr_time += 1
            self.pq.add_task(["policy_request", owner, self.id, [self]], curr_time)
        self.pq.check_queue()

    def receive_participants(self, operators, owners):
        self.operators = operators
        self.SDK.set_op_operator(operators)
        self.all_owners = owners

    def verify_key(self, verifier, hash, signature):
        try:
            verifier.verify(hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    def ver_final_decision(self, sender, start_time, expected_shares):
        print("ver_final_decision ", expected_shares)
        agreement = False
        if sender == self.access_leader:
            if expected_shares == len(self.valid_shares):
                self.STATUS = "share_info"
                agreement = True
        
        operator = self.operators[sender]
        self.pq.append_to_queue(["final_decision", operator, self.id, [agreement]], start_time + 1)

    def compare_policy(self, sender, polTree, curr_time):
        owner = self.owners[sender]
        decision = PolTree.process_access_request(polTree, self.attribute_set)
        delay = random.randint(1, 8)
        self.decisions[sender] = decision

        self.pq.append_to_queue(["verify", owner, self.id, [hash_message(decision, self.sig_pk), self.attribute_set, self, delay]], curr_time+delay+1)

    #Verify the signatures shared by the trusted key management
    #Forward the access decision to the access operator -- only the access decision
    def compare_access_ver(self, sender, share: Shares, sigshare, proof, start_time = None, timed = False):
        key = RSA.import_key(open('TKM_keys/public_key.pem').read())
        h_i = SHA512.new(str(share.index).encode('utf-8'))
        h_share = SHA512.new(share.share)
        verifier = pss.new(key)

        if timed:
            start = time.time()
            success_i = self.verify_key(verifier, h_i, share.index_signiture)
            success_share = self.verify_key(verifier, h_share, share.share_signature)

            decision = self.decisions.get(sender)
            correct_proof = self.verify_proof(self.sig_pk, proof, hash_message(decision, self.sig_pk), sigshare)
            end = time.time()
            return (end - start)
        else:
            verifier = pss.new(key)
            success_i = self.verify_key(verifier, h_i, share.index_signiture)
            success_share = self.verify_key(verifier, h_share, share.share_signature)

            decision = self.decisions.get(sender)
            correct_proof = self.verify_proof(self.sig_pk, proof, hash_message(decision, self.sig_pk), sigshare)

            if success_i and success_share and correct_proof and self.STATUS == "request":
                self.unverified_shares.append((sender, share, sigshare))
                access_operator = self.operators[self.access_leader]
                delay = random.randint(62, 67)
                start_time = start_time + delay
                self.pq.append_to_queue(["receive_access_decision", access_operator, self.id, [decision, sender]], start_time+1)

            else:
                self.pq.check_queue()

    def set_leaders(self, access_id, encryption_id):
        self.access_leader = access_id
        self.encryption_leader = encryption_id

    def compare_ack(self, sender_id, owner):
        remove_pair = None
        if sender_id == self.access_leader:
            self.acks += 1

        for pair in self.unverified_shares:
            owner_id, share, sigshare = pair
            if owner_id == owner:
                self.valid_shares.append(share)
                remove_pair = pair
                decision = self.decisions.get(owner_id)
                if decision == "Accept":
                    self.accepted.append(sigshare)
                else:
                    self.denied.append(sigshare)

        if remove_pair is not None:
            self.unverified_shares.remove(remove_pair)
        self.pq.check_queue()

    def provide_owner_info(self, sender, decision, start_time):
        if sender == self.encryption_leader:
            shares = self.valid_shares
            if decision == "Accept":
                signatures = self.accepted
            else:
                signatures = self.denied
            
            operator = self.operators[self.encryption_leader]
            self.pq.append_to_queue(["receive_info", operator, self.id, [signatures, shares]], start_time+1)

    def verify_proof(self, pk, proof, message, sigshare): 
        sig, id = sigshare
        xt = pow(message, 4, pk['n'])
        z, c = proof

        xp1 = pow(xt, z, pk['n'])
        xp2 = pow(sig, -2*c, pk['n'])

        vp1 = pow(pk['v'], z, pk['n'])
        vp2 = pow(pk['vs'][id-1], -c, pk['n'])

        ver_c = hash_transcript(v=pk['v'],
                                    xt=xt,
                                    vi=pk['vs'][id-1],
                                    xi2=pow(sig, 2, pk['n']),
                                    vp= (vp1*vp2) % pk['n'],
                                    xp=(xp1*xp2) % pk['n'])

        if ver_c == c:
            return True
        else:
            return False