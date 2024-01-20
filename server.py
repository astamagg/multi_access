import time
import uuid
import random
from ParticipantComponents.AccessLeader import AccessLeader
from ParticipantComponents.EncryptionDecryptionLeader import EncryptionDecryptionLeader
from ParticipantComponents.WorkerOperator import WorkerOperator
from ParticipantComponents.TrustedKeyManager import TrustedKeyManager
from ParticipantComponents.Owner import Owner
from Support.blockchain import Channel
from ParticipantComponents.Clients import Client
from Support.PolTree import PolTree
from os import urandom
from Support.Database import Database
import time
import math
from Support.priority_queue import PQ
import sys
from Support.util import print2D

class Server:
    def __init__(self):
        self.operators = {}
        self.owners = {}
        self.tkm = None
        self.pq = PQ()

    def reset(self):
        self.operators = {}
        self.owners = {}
        self.tkm = None
        self.pq = PQ()

    def send_ops(self, access_id, encryption_id):
        for i, operator in enumerate(self.operators.values()):
            operator.set_leaders(access_id, encryption_id)
            operator.receive_participants(self.operators, self.owners)

    def set_up_system(self, n_ops, n_owners, database_name, key_threshold, levels_of_access):
        channel_id = uuid.uuid4()
        self.channel = Channel(channel_id)
        access_leader_id, encryption_leader_id, worker_ids = self.set_up_operators(n_ops, self.channel, database_name, key_threshold, levels_of_access)
        owner_ids = self.set_up_owners(n_owners, self.channel)
        tkm_id = self.set_up_keygenerator(access_leader_id, encryption_leader_id)
        self.send_ops(access_leader_id, encryption_leader_id)

        return access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id

    def generate_ids(self, n):
        ids = []
        for i in range(n):
            ids.append(uuid.uuid4())
        return ids

    def set_up_operators(self, num_operators, channel_id, database_name, key_threshold, levels_of_access):
        if not num_operators > 2:
            raise AssertionError("System requires at least two operators")

        ids = self.generate_ids(num_operators)
        self.encryption_leader_id = ids[random.randint(0, len(ids))-1]
        self.operators[self.encryption_leader_id] = EncryptionDecryptionLeader(self.encryption_leader_id, channel_id, database_name, self.pq, key_threshold, levels_of_access)
        ids.remove(self.encryption_leader_id)

        self.access_leader_id = ids[random.randint(0, len(ids))-1]
        ids.remove(self.access_leader_id)
        self.operators[self.access_leader_id] = AccessLeader(self.access_leader_id, channel_id, key_threshold, self.pq, levels_of_access)

        for i in ids:
            self.operators[i] = WorkerOperator(i, channel_id, self.pq, key_threshold, levels_of_access)

        self.channel.set_endorsing_peers(self.operators)

        return self.access_leader_id, self.encryption_leader_id, ids

    def set_up_owners(self, n, channel_id):
        ids = self.generate_ids(n)

        for i in ids:
            self.owners[i] = Owner(i, channel_id, self.pq)

        self.channel.set_organizations(self.owners)

        return ids
    
    def set_up_keygenerator(self, access_leader_id, encryption_leader_id):
        self.tkm = TrustedKeyManager(id, self.owners, self.operators)
        return id

    def set_up_shares(self, tks_id, threshold, params, writing_file  = None, timed = False, testing = False):
        if testing:
            signed_shares, sig_shares, sig_pk, time_result = self.tkm.share_secrets(threshold, len(self.owners.keys()), params, timed, testing)
        else:
            self.tkm.share_secrets(threshold, len(self.owners.keys()), params, timed, testing)

        if timed:
            self.append_to_file(writing_file, str(time_result))
        if testing:
            return signed_shares, sig_shares, sig_pk

    def append_to_file(self, filename, string):
        f = open(filename, "a")
        f.write(string + "\n")
        f.close()

    def test_access_request(self, attribute_set, resource_id):
        client = Client(self.channel, attribute_set, uuid.uuid4())
        client.SDK.set_op_operator(self.operators)
        client.request_access(resource_id)

    def test_owner_policy(self, filenames):
        policy_zero = 0
        policy_one = 0
        for i, owner in enumerate(self.owners.values()):
            if len(filenames) > 1:
                if i == 1 or i == 3:
                    policy_zero += 1
                    owner.generateTree(filenames[0])
                else:
                    if (i) % 2 == 0:
                        policy_one += 1
                        owner.generateTree(filenames[0])
                    else:
                        policy_zero += 1
                        owner.generateTree(filenames[1])

            else:
                owner.generateTree(filenames[0])

        print("ZERO POLICY: ", policy_zero)
        print("ONE POLICY: ", policy_one)

    def test_key_reconstruction(self, shares, level, filename=None, memory=False):
        if memory:
            encryption_op = self.operators[self.encryption_leader_id]
            keys = encryption_op.reconstruct_keys(shares, level)
            return keys
        else:
            encryption_op = self.operators[self.encryption_leader_id]
            start = time.process_time()
            keys = encryption_op.reconstruct_keys(shares, level)
            end = time.process_time()
            self.append_to_file(filename, str((end - start)))

    def test_sig_reconstruction(self, param, pk, sigshares, message, filename=None, memory=False):
        if memory:
            encryption_op = self.operators[self.encryption_leader_id]
            signature = encryption_op.reconstruct_signature_shares(param, pk, sigshares, message)

            return signature
        else:
            encryption_op = self.operators[self.encryption_leader_id]
            start = time.time()
            encryption_op.reconstruct_signature_shares(param, pk, sigshares, message)
            end = time.time()

            self.append_to_file(filename, str((end - start)))

    def memory_reconstruction(self, param, pk, sigshares, message, keyshares, level, memory=True):
        encryption_op = self.operators[self.encryption_leader_id]
        signature = self.test_sig_reconstruction(param, pk, sigshares, message, memory=True)
        keys = self.test_key_reconstruction(keyshares, level,memory=True )
        print("signature size: {}".format(sys.getsizeof(signature)))
        #print(keys[0][1])
        #print(sys.getsizeof(keys[0][1]))
        #print(sys.getsizeof(keys[1][1]))

    def test_generating_tree(self, policy, owner_id, size=False):
        if size:
            owner = self.owners[owner_id]
            owner.generateTree(policy)
            return owner.polTree.byte_size(owner.polTree.tree.root), owner.polTree.height(owner.polTree.tree.root), owner.polTree.size(owner.polTree.tree.root)
        else:
            start = time.time()
            owner = self.owners[owner_id]
            owner.generateTree(policy)
            end = time.time()

            return((end-start))

    def set_up_storage_transaction(self, resource_id, ownerlist, public_key):
        partial_public_key = dict()
        partial_public_key['n'] = public_key['n']
        partial_public_key['e'] = public_key['e']
        string_ownerlist = [str(owner) for owner in ownerlist]
        self.channel.new_storage_transactions(str(resource_id), string_ownerlist, partial_public_key)

    def encrypt_a_file(self, file_name, shares, level, encryption_leader_id, resource_id):
        eleader = self.operators[encryption_leader_id]
        keys = eleader.reconstruct_keys(shares, level)
        iv = urandom(16)

        f = open(file_name, mode='r')
        content = f.read()
        f.close()

        eleader.encrypt(iv, keys, content.encode('utf-8'), 1, resource_id)

    #Testing encryption
    def test_encryption(self, encryptionTexts, encryption_leader_id, shares, database_name, resource_id, encryption_file, decryption_file, size) -> ():
        f_encrypt = open(encryption_file, "w+")
        f_encrypt.close()

        f_decrypt = open(decryption_file, "w+")
        f_decrypt.close()
        eleader = self.operators[encryption_leader_id]
        keys = eleader.reconstruct_keys(shares, 1)
 
        if size:
            string_parts = encryptionTexts[0].split("_")
            self.append_to_file(encryption_file, string_parts[1])
            self.append_to_file(decryption_file, string_parts[1])

        for file_name in encryptionTexts:
            if size:
                curr_string_parts = file_name.split("_")
                if string_parts[1] != curr_string_parts[1]:
                    string_parts = curr_string_parts
                    self.append_to_file(encryption_file, string_parts[1])
                    self.append_to_file(decryption_file, string_parts[1])
                resource_id = uuid.uuid4()

            iv = urandom(16)
            f = open(file_name, mode='r')
            content = f.read()
            f.close()
            start_encrypt = time.time()
            eleader.encrypt(iv, keys, content.encode('utf-8'), 1, resource_id)
            end_encrypt = time.time()
            time_result = end_encrypt - start_encrypt

            self.append_to_file(encryption_file, str(time_result))

            start_decrypt = time.time()
            plaintexts = eleader.decrypt(resource_id, 1, keys, testing=True)
            assert(content.encode('utf-8') == plaintexts[len(plaintexts)-1])

            end_decrypt = time.time()
            time_result = end_decrypt - start_decrypt

            self.append_to_file(decryption_file, str(time_result))

    def test_encryption_memory(self, byte_counts, counts, encryption_leader_id, shares, database_name, resource_id, memory_file_path):
        eleader = self.operators[encryption_leader_id]
        keys = eleader.reconstruct_keys(shares, 1)

        for byte in byte_counts:
            memory_file = "{}_{}".format(memory_file_path, byte)
            f_encrypt = open(memory_file, "w+")
            f_encrypt.close()
            for count in counts:
                filename = "plaintexts/output_{}_count_{}.txt".format(byte, count)
                iv = urandom(16)
                f = open(filename, mode='r')
                content = f.read()

                ciphertext, authtag, signature = eleader.encrypt(iv, keys, content.encode('utf-8'), 1, resource_id, testing_memory=True)
                print(len(signature))
                results = "{}, {}, {}".format(sys.getsizeof(ciphertext), sys.getsizeof(authtag), sys.getsizeof(signature))
                self.append_to_file(memory_file, results)

    def test_database(self, database_name):
        self.db = Database(database_name)

    def set_up_bounds(self, eleader_id, lbound, ubound, event_file, message_file):
        eleader = self.operators[eleader_id]
        eleader.receive_bounds(lbound, ubound, event_file, message_file)

    def test_run(self, owner_count, operator_count, attribute_set, resource_id, levels_of_access, threshold_owners, access_policy, param, encryption_file, level, database_name, lower_bound, upper_bound, event_file, message_file):
        access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = self.set_up_system(operator_count, owner_count, database_name, threshold_owners, levels_of_access)
        key_shares, sig_shares, pk = self.set_up_shares(tkm_id, 3, param, testing=True)
        self.set_up_storage_transaction(resource_id, owner_ids, pk)
        self.set_up_bounds(encryption_leader_id, lower_bound, upper_bound, event_file, message_file)
        self.encrypt_a_file(encryption_file, key_shares, level, encryption_leader_id, resource_id)
        self.test_owner_policy(access_policy)
        self.test_access_request(attribute_set, resource_id)

#server = Server()
#database_name = "test"
#owner_count, ops_count = create_owner_list()

#param = {
        # RSA modulus length, in bits.
        # A toy value suitable for testing is, e.g., 100.
        # A more realistic value is, e.g., 3072
#        'rsa_modulus_length_in_bits': 3072,
        # Number of signature shares needed to obtain a signature.
        # This is k in the paper.
#        'number_parties_needed': 2,
        # Number of players engaging in the protocol. This is l in the paper.
#        'number_parties_total': 2,
        # This is t in the paper. max k-1. Currently unused in this code.
#        'number_parties_corrupted': 0,
#        "e": 0x10001,
#}

#owner_count = 2
#operator_count = 4
#levels_of_access = {2: 1} # TODO fix this
#resource_id = uuid.uuid4()
#access_policy = 'access_policies/ruleset_6.json'
#attribute_set = ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"]
#file_to_encrypt = 'plaintexts/output_10_count_1.txt'

#server.test_run(owner_count, operator_count, attribute_set, resource_id, levels_of_access, 0.51, access_policy, param, file_to_encrypt, 1, database_name)

#access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(4, 10, database_name, 0.51, levels_of_access)
#resource_id = uuid.uuid4()
#key_shares, sig_shares, pk = server.set_up_shares(tkm_id, 3, param, testing=True)

#server.set_up_storage_transaction(resource_id, owner_ids, pk)
#resource_id = uuid.uuid4()
#server.set_up_storage_transaction(resource_id, owner_ids, pk)

#server.test_database(database_name)

#server.test_owner_policy('access_policies/ruleset_6.json')

#server.test_access_request(["Professor", "ECE", "Assignment", "Low", "Weekday", "Read"], resource_id)
#server.test_access_request(["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"], resource_id)
