from Support.PolTree import PolTree, Policy
import secrets
from Support.util import hash_transcript, hash_message
import json
import time
from queue import Queue
import random

#@ray.remote
class Owner:
    def __init__(self, id, channel_id, pq):
        self.id = id
        self.key_share = None
        self.channel_id = channel_id
        self.urandom = secrets.SystemRandom()
        self.sk_share = None
        self.sig_pk = None
        self.pq = pq
        self.message_queue = Queue()

    #consider if owners should be able to verify signatures of the shares they receive
    # Or do we trust the communication with the trusted key manager
    def receive_share(self, share, signature_share, sig_pk):
        self.key_share = share
        self.sk_share = signature_share
        self.sig_pk = sig_pk

    def receive_message(self, message_type, sender, arguments, start_time):
        self.message_queue.put((message_type, sender, arguments, start_time))
        self.check_queue()

    def check_queue(self):
        processed = False
        if not self.message_queue.empty():
            next_task = self.message_queue.get()
            message_type = next_task[0]
            if message_type == "verify":
                processed = True
                self.verify_policy(next_task[2][0], next_task[2][1], next_task[2][2], next_task[3], delay=next_task[2][3])
            elif message_type == "policy_request":
                processed = True
                self.policy_request(next_task[2][0], next_task[3])
            else:
                ValueError('Invalid message type')

        if not processed:
            self.pq.check_queue()
                

    def generateTree(self, filename):
        policy = Policy()
        
        with open(filename, 'r+') as f:
            data = json.load(f)
            for rule in data['rules']:
                attributes = []
                values = []
                for key in rule:
                    attributes.append(key)
                    values.append(rule[key])
                policy.create_rule(attributes, values)
        policy.order_avp(policy.avp_list)

        self.polTree = PolTree(policy)
        sorted_frequencies = sorted(policy.frequencies, key=policy.frequencies.get, reverse=True)
        self.polTree.gen_bin_tree(policy.rules, sorted_frequencies)

    def policy_request(self, sender, start_time):
        self.pq.append_to_queue(["policy", sender, self.id, [self.polTree.tree]], start_time+1)
    
    #TODO add advesarial behavior
    def verify_policy(self, decision, attribute_set, sender, start_time, delay=None, testing = False):
        owner_decision = PolTree.process_access_request(self.polTree.tree, attribute_set)

        if testing:
            start = time.time()
            hash_owner_decision = hash_message(owner_decision, self.sig_pk)
            sigshare = self.signature_share(hash_owner_decision)
            proof = self.construct_proof(hash_owner_decision, sigshare)
            end = time.time()
            result = end - start
        else:
            hash_owner_decision = hash_message(owner_decision, self.sig_pk)
            sigshare = self.signature_share(hash_owner_decision)
            proof = self.construct_proof(hash_owner_decision, sigshare)

        if hash_owner_decision == decision:
            if testing:
                return self.key_share, sigshare, proof, result
            else:
                #sender.receive_verification(self.id, [self.key_share, sigshare, proof])
                construction_delay = random.randint(70, 75)
                start_time = start_time + construction_delay + delay
                self.pq.append_to_queue(["policy_response", sender, self.id, [self.key_share, sigshare, proof]], start_time+1)

    def signature_share(self, message):
        exponent = 2 * self.sk_share[1]
        xi = pow(message, exponent, self.sig_pk['n'])

        return (xi, self.sk_share[0])

    def construct_proof(self, message, sigshare):
        sig, _ = sigshare
        id, sk = self.sk_share
        xt = pow(message, 4, self.sig_pk['n'])
        r = self.urandom_num(self.sig_pk['n'])
                
        c = hash_transcript(v=self.sig_pk['v'],
                                xt=xt,
                                vi=self.sig_pk['vs'][id-1],
                                xi2=pow(sig, 2, self.sig_pk['n']),
                                vp=pow(self.sig_pk['v'], r, self.sig_pk['n']),
                                xp=pow(xt, r, self.sig_pk['n']))
                 
        z = (sk*c) + r
        proof = (z, c)

        return proof

    def urandom_num(self, n):
        return self.urandom.randint(0, n-1)  # inclusive 0 and n-1