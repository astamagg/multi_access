from os import urandom
from Support.protocols import ShamirSecretSharing
from typing import List, Tuple
from hashlib import sha256
from Crypto.Cipher import AES
from Support.SDK import SDK
from Support.util import lagrange, gcd_extended, hash_message
import sys
from Crypto.Util.Padding import pad, unpad
from Support.Database import Database
from base64 import b64encode, b64decode
from queue import Queue
import random
from Support.util import append_to_file

# I can also just encrypt a ton of documents and add them to the local database, because this is not really the main part of my protocol
# Need to think a bit better about how the encryption is done
class EncryptionDecryptionLeader:
    def __init__(self, id, channel, database_name, pq, key_threshold, levels_of_access):
        self.id = id
        self.signing_literal = b'Signing key' #Literal concatinated with the hashing of the key
        self.encryption_literal = b'Encryption key' #TODO should reconsider where these should be decided
        self.operators = {}
        self.SDK = SDK(channel)
        self.sig_params = None
        self.signatures = []
        self.shares = []
        self.sig_pk = None
        self.responses = 0
        self.db = Database(database_name)
        self.database_name = database_name
        self.STATUS = "free"
        self.pq = pq
        self.message_queue = Queue()
        self.key_threshold = key_threshold
        self.levels_of_access = levels_of_access

    def receive_message(self, message_type, sender, arguments, start_time):
        self.message_queue.put((message_type, sender, arguments, start_time))
        self.check_queue()

    def receive_bounds(self, lower_bound, upper_bound, event_file, message_file):
        self.reconstruction_bounds = ((lower_bound, upper_bound))
        self.event_file = event_file
        self.message_file = message_file

    def check_queue(self):
        processed = False
        next_task = self.message_queue.get()
        message_type = next_task[0]
        if message_type == "access_request":
            processed = True
            self.access_request(next_task[2][0], next_task[2][1], next_task[2][2], next_task[3])
        if message_type == "access_decision":
            processed = True
            self.receive_access_decision(next_task[2][0], next_task[2][1], next_task[3])
        if message_type == "receive_info" and self.STATUS == "access_decision":
            processed = True
            self.receive_owner_information(next_task[2][0], next_task[2][1], next_task[3])
        
        if not processed:
            self.pq.check_queue()

    def set_leaders(self, access_id, encryption_id):
        self.access_leader = access_id
        self.encryption_leader = encryption_id

    def receive_signing_params(self, pk, params):
        self.sig_params = params
        self.sig_pk = pk

    def receive_participants(self, operators, owners):
        self.operators = operators
        self.SDK.set_op_operator(operators)
        self.owners = owners
    
    #Reconstruct the correct key baased on the level of access required for encryption or allowed for decryption
    def reconstruct_keys(self, collected_shares, level_of_access: int, testing=False) -> Tuple[int, bytes, bytes]:
        encryption_key = ShamirSecretSharing.reconstructSecret(collected_shares)
        keys = list()
        keys.append((0, encryption_key, b''))
        print("level of access: ", level_of_access)

        for i in range(level_of_access):
            key_hash = sha256(encryption_key).digest()
            level_signing_key = sha256(key_hash + self.signing_literal).digest()
            level_encryption_key = sha256(key_hash + self.encryption_literal).digest()

            keys.append((i+1, level_encryption_key, level_signing_key))
            
        return keys

    def access_request(self, attribute_set, resource_id, requester_id, start_time):
        self.requester = requester_id
        self.resource = resource_id
        # TODO might need to add a response if no access has taken

    def encrypt_value(self, encryption_key, signing_key, iv, text):
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)
        ciphertext, auth_tag = cipher.encrypt_and_digest(text)
        signature = sha256(ciphertext + signing_key).digest()

        return ciphertext, auth_tag, signature


    #Encryption uses AES 256 - GCM mode. GCM mode has a tag is used for authentication
    def encrypt(self, iv: bytes, key: bytes, text: bytes, level: int, resource_id, testing_memory=False) -> (bytes, bytes, bytes):
        level_of_access, encryption_key, signing_key = key[level]
        
        #cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)
        #ciphertext, auth_tag = cipher.encrypt_and_digest(text)
        #signature = sha256(ciphertext + signing_key).digest()
        ciphertext, auth_tag, signature = self.encrypt_value(encryption_key, signing_key, iv, text)

        level_of_access, encryption_key, signing_key = key[0]        
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)
        cipher_level, level_auth_tag = cipher.encrypt_and_digest(pad(bytes(level), 16))

        ciphertext_level = b64encode(cipher_level).decode('utf-8') + " " + b64encode(level_auth_tag).decode('utf-8')

        if testing_memory:
            return ciphertext, auth_tag, signature
        else:
            self.db.insert_query(self.database_name, str(resource_id), ciphertext_level, b64encode(ciphertext).decode('utf-8'), iv, b64encode(auth_tag).decode('utf-8'), signature)

    def decrypt(self, resource_id, level, keys, testing=False):
        results = self.db.level_query(self.database_name, resource_id)
        plaintexts = []
        
        for result in results:
            resource_id = result[0]
            level_tag = result[1]
            iv = result[3]

            clevel, tag = level_tag.split(" ")
        
            base_key = keys[0][1]

            cipher = AES.new(base_key, AES.MODE_GCM, nonce=iv)     
            plaintext = unpad(cipher.decrypt_and_verify(b64decode(clevel), b64decode(tag)), 16)
            curr_level = int.from_bytes(plaintext, byteorder=sys.byteorder)

            if curr_level <= level:
                _, encryption_key, signing_key = keys[level]
                cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)     
                plaintext = cipher.decrypt_and_verify(b64decode(result[2]), b64decode(result[4]))

                signature_computation = sha256(b64decode(result[2]) + signing_key).digest()
                if signature_computation == result[5]:
                    plaintexts.append(plaintext)
                else:
                    raise Exception("Data is tampered")

        if testing:
            return plaintexts

        else:
            if not plaintexts:
                print("No results")
            else:
                print("Results ", plaintexts)

    def receive_owner_information(self, signature, share, start_time):
        self.signatures.extend(signature)
        self.shares.extend(share)

        self.responses += 1

        if self.responses == (len(self.operators.keys()) - 2):
            self.STATUS = "reconstructing"
            self.reconstruct(start_time)
        else:
            self.pq.check_queue()

    def reconstruct(self, start_time = None, memory=False):
        delay = 0
        if self.decision == "Accept":
            delay += random.randint(1, 3)
            keys = self.reconstruct_keys(self.shares, self.level)
            plaintexts = self.decrypt(self.resource, self.level, keys)
        else:
            keys = self.reconstruct_keys(self.shares, 0)

        iv = urandom(16)
        level_of_access, encryption_key, signing_key = keys[0]
        delay += random.randint(self.reconstruction_bounds[0], self.reconstruction_bounds[1])
        encrypted_requester, _, _ = self.encrypt_value(encryption_key, signing_key, iv, self.requester.bytes)
        requester = '{}_{}'.format(encrypted_requester, iv)
        append_to_file(self.event_file, start_time+delay)
        append_to_file(self.message_file, self.pq.message_count)

        access_decision = self.decision + ':' + str(self.level)
        combined_signature = self.reconstruct_signature_shares(self.sig_params, self.sig_pk, self.signatures, hash_message(self.decision, self.sig_pk))
        print("SENT TRANSACTION: ", start_time + delay)
        print("MESSAGE COMPLEXITY: ", self.pq.message_count)
        if memory:
            return combined_signature, keys
        else:
            self.SDK.access_transaction(self.resource, requester, access_decision, combined_signature, None)

    def receive_access_request(self, attribute_set, requester_id, resource_id, owners):
        # TODO add a timeout for the response of the access leader, start a reelection of the access leader
        pass

    def receive_access_decision(self, decision, level, start_time):
        print("receive_access_decision: ", decision)
        self.STATUS = "access_decision"
        self.decision = decision
        self.level = level
        curr_time = start_time
        for id in self.operators:
            if id != self.access_leader and id != self.encryption_leader:
                curr_time += 1
                operator = self.operators[id]
                self.pq.add_task(["owner_info", operator, self.id, [decision]], curr_time)
                #operator.receive_owner_info_request(self.id, decision)
        self.pq.check_queue()
        
    def reconstruct_signature_shares(self, param, pk, sigshares, message):
        e = pk['e']
        delta = param['delta']
        e_prime = 4
        (gcd_e_eprime, bezout_a, bezout_b) = gcd_extended(e_prime, e)

        assert(gcd_e_eprime == 1)

        quorum = []
        print("number of needed parties: ", param['number_parties_needed'])
        print("number of sigshares: ", len(sigshares))
        for j in range(param['number_parties_needed']):
            quorum.append(sigshares[j][1])

        sigshares = sigshares[0: param['number_parties_needed']]

        w = 1
        for sigshare in sigshares:
            exponent = 2 * lagrange(quorum, 0, sigshare[1], delta)
            part = pow(sigshare[0], exponent, pk['n'])

            w = (w * part) % pk['n']

        assert(pow(w, e, pk['n']) == pow(message, e_prime, pk['n']))

        p1 = pow(w, bezout_a, pk['n'])
        p2 = pow(message, bezout_b, pk['n'])
        signature_recombined = (p1*p2) % pk['n']

        assert((pow(signature_recombined, e, pk['n'])) == message)
        return signature_recombined

