from Support.protocols import ShamirSecretSharing
from ParticipantComponents.EncryptionDecryptionLeader import EncryptionDecryptionLeader
from os import urandom
import time
from hashlib import sha256
import uuid
from Support.blockchain import Channel
import binascii
import math
from server import Server
from Support.util import hash_message
import string
import random
import json
from Support.PolTree import PolTree
import os
import sys
from visualization import read_file, calc_gap

#Testing shamir secret sharing
def test_shamir(t: int, n: int) -> ():
    key = urandom(32)

    total_shares = ShamirSecretSharing.computeSecrets(t,n,key)
    t_shares = total_shares[:t]
    reconstructed_key = ShamirSecretSharing.reconstructSecret(t_shares)

#Testing encryption
def test_encryption(encryptionText: bytes, id, channel) -> ():
    eleader = EncryptionDecryptionLeader(id, channel)
    currentKey = urandom(32)
    iv = urandom(16)
    ctext, tag = eleader.encrypt(iv, currentKey, encryptionText, 1)

    bText = eleader.decrypt(iv, currentKey, ctext, tag)

    print("Verifying encryption: {}".format(encryptionText == bText))

#testing key construction and verification
def test_key_construction():
    eLeader = EncryptionDecryptionLeader()
    text = b'test'
    ciphertext, sig, sig_key = eLeader.encryptionRequest(text, b'1', 1)

    verify_hash = sha256(ciphertext + sig_key).digest()

    print("verifying signature: {}".format(sig == verify_hash))

def create_plaintext_files(kb_size, count, byte_sizes):
    for size in byte_sizes:
        for i in count:
            encryption_file = "plaintexts/output_{}_count_{}.txt".format(size, i)
            with open(encryption_file, 'wb') as fout:
                fout.write(binascii.hexlify(urandom(size)))

def number_of_operators(num_owners, threshold):
    #Lowest possible count of owners an operator can receive without crossing the threshold
    threshold_count = num_owners * threshold

    if threshold_count.is_integer():
        threshold_count = int(threshold_count) - 1
    else:
        threshold_count = math.ceil(threshold_count)

    modulus = num_owners % threshold_count
    num_ops = num_owners // threshold_count

    if modulus != 0:
        num_ops += 1
        
    return num_ops + 2
        

def create_owner_list(threshold):
    owner_count = []
    ops_count = []

    owner_count.append(2)
    ops_count.append(number_of_operators(2, threshold)+1)
    owner_count.append(5)
    ops_count.append(number_of_operators(5, threshold))

    every_tenth = list(range(10, 49))
    every_tenth = every_tenth[0::10]

    every_fifty = list(range(50, 201))
    every_fifty = every_fifty[0::25]

    every_tenth.extend(every_fifty)

    for value in every_tenth:
        owner_count.append(value)
        ops_count.append(number_of_operators(value, threshold))

    return owner_count, ops_count

def benchmark_encryption(count, byte_sizes, threshold, owner_total, operators, size, threshold_of_owners, levels_of_access):
    server = Server()
    database_name = "test"
    files = []

    param = {
        # RSA modulus length, in bits.
        # A toy value suitable for testing is, e.g., 100.
        # A more realistic value is, e.g., 3072
        'rsa_modulus_length_in_bits': 2048,
        # Number of signature shares needed to obtain a signature.
        # This is k in the paper.
        'number_parties_needed': threshold,
        # Number of players engaging in the protocol. This is l in the paper.
        'number_parties_total': owner_total,
        # This is t in the paper. max k-1. Currently unused in this code.
        'number_parties_corrupted': 0,
        "e": 0x10001,
    }

    if size:
        for byte in byte_sizes:
            for i in count:
                file_name = "plaintexts/output_{}_count_{}.txt".format(byte, i)
                files.append(file_name)
    else:
        for i in count:
            for byte in byte_sizes:
                file_name = "plaintexts/output_{}_count_{}.txt".format(byte, i)
                files.append(file_name)

    access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(operators, owner_total, database_name, threshold_of_owners, levels_of_access)
    shares, sig_shares, pk = server.set_up_shares(tkm_id, threshold, param, testing=True)

    resource_id = uuid.uuid4()
    if size:
        server.test_encryption(files, encryption_leader_id, shares, database_name, resource_id, "times/encrypt_decrypt/encrypt_size.txt", "times/encrypt_decrypt/decrypt_size.txt", size)
    else:
        for i in count:
            server.test_encryption(files, encryption_leader_id, shares, database_name, resource_id, "times/encrypt_decrypt/encrypt_count_{}.txt".format(i), "times/encrypt_decrypt/decrypt_count_{}.txt".format(i), size)

def benchmark_memory_encryption(count, byte_sizes, threshold, owner_total, operators, size, threshold_of_owners, levels_of_access):
    server = Server()
    database_name = "test"
    files = []

    param = {
        # RSA modulus length, in bits.
        # A toy value suitable for testing is, e.g., 100.
        # A more realistic value is, e.g., 3072
        'rsa_modulus_length_in_bits': 3072,
        # Number of signature shares needed to obtain a signature.
        # This is k in the paper.
        'number_parties_needed': threshold,
        # Number of players engaging in the protocol. This is l in the paper.
        'number_parties_total': owner_total,
        # This is t in the paper. max k-1. Currently unused in this code.
        'number_parties_corrupted': 0,
        "e": 0x10001,
    }

    access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(operators, owner_total, database_name, threshold_of_owners, levels_of_access)
    shares, sig_shares, pk = server.set_up_shares(tkm_id, threshold, param, testing=True)
    print(pk)
    print(sys.getsizeof(pk['v']))
    resource_id = uuid.uuid4()
    server.test_encryption_memory(byte_sizes, count, encryption_leader_id, shares, database_name, resource_id, "results/encryption_memory/")

def benchmark_memory_reconstruction(sig_threshold, decision, access_file, attribute_set, key_threshold, memory=True, writing_file=None):
    owner_count, ops_count = create_owner_list(sig_threshold)
    server = Server()
    database_name = "test"

    for i in range(len(owner_count)):
        #print(owner_count[i])
        #curr_file = "{}.txt".format(writing_file, owner_count[i])
        #f = open(curr_file, "w+")
        #f.close()
        owner_threshold = math.ceil(owner_count[i]*sig_threshold)

        param = {
            # RSA modulus length, in bits.
            # A toy value suitable for testing is, e.g., 100.
            # A more realistic value is, e.g., 3072
            'rsa_modulus_length_in_bits': 2048,
            # Number of signature shares needed to obtain a signature.
            # This is k in the paper.
            'number_parties_needed': owner_threshold,
            # Number of players engaging in the protocol. This is l in the paper.
            'number_parties_total': owner_count[i],
            # This is t in the paper. max k-1. Currently unused in this code.
            'number_parties_corrupted': 0,
            "e": 0x10001,
        }


        access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(ops_count[i], owner_count[i], database_name, key_threshold, levels_of_access)
        shares, sig_shares, pk = server.set_up_shares(tkm_id, owner_threshold, param, writing_file, timed=False, testing=True)

        print(pk)
        print(sys.getsizeof(pk['v']))
        hashed_decision = hash_message(decision, pk)
        server.test_owner_policy(access_file)
        signature_shares = []

        for owner in server.owners.values():
            share, sig_share, proof, _ = owner.verify_policy(hashed_decision, attribute_set, worker_ids[0], None, testing=True)
            signature_shares.append(sig_share)

        server.memory_reconstruction(param, pk, signature_shares, hashed_decision, shares, 1)
        server.reset()


def benchmark_verify_shares(count, writing_file, owner_ver, attribute_set, access_file, decision, key_threshold, levels_of_access, sig_threshold, memory=False):
    print("access file ", access_file)
    #owner_count, ops_count = create_owner_list(sig_threshold)
    owner_count = [2]
    ops_count = [4]

    server = Server()
    database_name = "test"

    for i in range(len(owner_count)):
        print(owner_count[i])
        curr_file = "{}.txt".format(writing_file, owner_count[i])
        f = open(curr_file, "w+")
        f.close()
        owner_threshold = math.ceil(owner_count[i]*sig_threshold)

        param = {
            # RSA modulus length, in bits.
            # A toy value suitable for testing is, e.g., 100.
            # A more realistic value is, e.g., 3072
            'rsa_modulus_length_in_bits': 2048,
            # Number of signature shares needed to obtain a signature.
            # This is k in the paper.
            'number_parties_needed': owner_threshold,
            # Number of players engaging in the protocol. This is l in the paper.
            'number_parties_total': owner_count[i],
            # This is t in the paper. max k-1. Currently unused in this code.
            'number_parties_corrupted': 0,
            "e": 0x10001,
        }


        access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(ops_count[i], owner_count[i], database_name, key_threshold, levels_of_access)
        shares, sig_shares, pk = server.set_up_shares(tkm_id, owner_threshold, param, testing=True)
        #total = 0
        #for value in list(pk.keys()):
        #    if value != "vs":
        #        print(value)
        #        total += sys.getsizeof(pk[value])

        worker_operator = server.operators[worker_ids[0]]
        owner = server.owners[owner_ids[0]]
        server.test_owner_policy(access_file)
        worker_operator.set_request(attribute_set, server.owners, decision, owner_ids[0])
        hashed_decision = hash_message(decision, pk)
        
        if memory:
            share, sig_share, proof, owner_result = owner.verify_policy(hashed_decision, attribute_set, worker_ids[0], 0, True, testing=True)
            print("signature share: {}".format(sys.getsizeof(sig_share[0])+sys.getsizeof(sig_share[1])))
            server.reset()
        else:
            for i in count:
                if owner_ver:
                    share, sig_share, proof, owner_result = owner.verify_policy(hashed_decision, attribute_set, worker_ids[0], 0, testing=True)
                    server.append_to_file(curr_file, str(owner_result))
                else:
                    share, sig_share, proof, owner_result = owner.verify_policy(hashed_decision, attribute_set, worker_ids[0], 0, testing=True)
                    worker_result = worker_operator.compare_access_ver(owner_ids[0], share, sig_share, proof, 0, True)
                    server.append_to_file(curr_file, str(worker_result))
            server.reset()

def generate_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def create_attribute_set(access_file, value_length):
    attributes = []
    with open(access_file, 'r+') as f:
        data = json.load(f)
    
    rules = data['rules']    
    rand_rule = random.randint(0, len(rules)-1)
    rule = rules[rand_rule]
    correct_values = random.choice([True,False])
    for key in rule:
        if correct_values:
            value = rule[key]
        else:
            value = generate_string(value_length + 2)

        attributes.append(value)

    return attributes, correct_values

def make_access_policy(no_attributes, no_rules, no_values, attribute_length, value_length, write_file):
    attribute_values = dict()
    for i in range(no_attributes):
        result_string = generate_string(attribute_length)
        attribute_values[result_string] = list()

    values = set()

    for attribute in attribute_values.keys():
        for i in range(no_values):
            random_string = generate_string(value_length)
            values = attribute_values[attribute]
            values.append(random_string)

    policy = {}
    policy['rules'] = []
    attribute_set = []

    while(no_rules > 0):
        rule = {}
        for attribute in attribute_values.keys():
            values = attribute_values[attribute]
            rand_int = random.randint(0, len(values)-1)
            value = values[rand_int]
            rule[attribute] = value

        if rule not in policy['rules']:
            policy['rules'].append(rule)
        no_rules = no_rules - 1
    
    with open(write_file, 'w') as outfile:
        json_pretty = json.dumps(policy, indent=4)
        outfile.write(json_pretty)


def benchmark_set_up(count, levels_of_access, key_threshold, sig_threshold):
    server = Server()
    database_name = "test"
    owner_count, ops_count = create_owner_list(sig_threshold)

    for i in range(len(owner_count)):
        print(owner_count[i])
        writing_file = "times/setup/bigger_gap/owner_count_{}".format(owner_count[i])
        f = open(writing_file, "w+")
        f.close()
        owner_threshold = math.ceil(owner_count[i]*sig_threshold)

        param = {
            # RSA modulus length, in bits.
            # A toy value suitable for testing is, e.g., 100.
            # A more realistic value is, e.g., 3072
            'rsa_modulus_length_in_bits': 2048,
            # Number of signature shares needed to obtain a signature.
            # This is k in the paper.
            'number_parties_needed': owner_threshold,
            # Number of players engaging in the protocol. This is l in the paper.
            'number_parties_total': owner_count[i],
            # This is t in the paper. max k-1. Currently unused in this code.
            'number_parties_corrupted': 0,
            "e": 0x10001,
        }

        access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(ops_count[i], owner_count[i], database_name, key_threshold, levels_of_access)
            
        for j in count:
            shares, sig_shares, pk = server.set_up_shares(tkm_id, owner_threshold, param, writing_file, True, testing=True)
        
        server.reset()

def benchmark_policy(policy_name, file_range, count, ops_count, owner_count, database_name, write_file, generate_Tree, value_length, threshold_owners, levels_of_access):
    server = Server()
    access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(ops_count, owner_count, database_name, threshold_owners, levels_of_access)

    for in_file in file_range:
        for i in count:
            policy = "{}_{}_{}.json".format(policy_name, in_file, i)
            writing_file = "{}_{}.txt".format(write_file, in_file)

            f = open(write_file, "w+")
            f.close()
            if generate_Tree:
                result, heigth, size = server.test_generating_tree(policy, owner_ids[0], size=True)
                #print("RESULT: ", result)
                server.append_to_file(writing_file,("Size of policy file: {}, size of policy: {}, tree height: {}, tree size: {}".format(str(os.path.getsize(policy)), str(result), str(heigth), str(size))))
            else:
                result = server.test_generating_tree(policy, owner_ids[0])

                attribute_set, correct_value = create_attribute_set(policy, in_file)
                owner = server.owners[owner_ids[0]]
                start = time.time()
                decision = PolTree.process_access_request(owner.polTree.tree, attribute_set)
                end = time.time()
                server.append_to_file(writing_file, str((end-start)))

                decision_bool = False
                if decision == 'Accept':
                    decision_bool = True
                
                assert(decision_bool == correct_value)

def benchmark_reconstruction(levels_of_access, decision, key_threshold, sig_threshold, access_file = None, attribute_set = None, key_reconstruct = True):
    server = Server()
    database_name = "test"
    owner_count, ops_count = create_owner_list(sig_threshold)
    levels = list(levels_of_access.values())

    for i in range(len(owner_count)):
        print(owner_count[i])
        if key_reconstruct:
            writing_file = "times/reconstruction/keys/key_reconstruct_process_{}".format(owner_count[i])
        else:
            writing_file = "times/reconstruction/signatures/sig_reconstruct_process_{}".format(owner_count[i])
        f = open(writing_file, "w+")
        f.close()
        owner_threshold = math.ceil(owner_count[i]*sig_threshold)

        param = {
            # RSA modulus length, in bits.
            # A toy value suitable for testing is, e.g., 100.
            # A more realistic value is, e.g., 3072
            'rsa_modulus_length_in_bits': 2048,
            # Number of signature shares needed to obtain a signature.
            # This is k in the paper.
            'number_parties_needed': owner_threshold,
            # Number of players engaging in the protocol. This is l in the paper.
            'number_parties_total': owner_count[i],
            # This is t in the paper. max k-1. Currently unused in this code.
            'number_parties_corrupted': 0,
            "e": 0x10001,
        }

        access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(ops_count[i], owner_count[i], database_name, key_threshold, levels_of_access)
        shares, sig_shares, pk = server.set_up_shares(tkm_id, owner_threshold, param, writing_file, timed=False, testing=True)
        hashed_decision = hash_message(decision, pk)
        server.test_owner_policy(access_file)
        signature_shares = []

        for owner in server.owners.values():
            share, sig_share, proof, _ = owner.verify_policy(hashed_decision, attribute_set, worker_ids[0], None, testing=True)
            signature_shares.append(sig_share)
        
        if key_reconstruct:
            for level in levels:
                server.append_to_file(writing_file, str(level))
                for j in count:
                    server.test_key_reconstruction(shares, level, writing_file)
        else:
            for j in count:
                hashed_decision = hash_message(decision, pk)
                server.test_sig_reconstruction(param, pk, signature_shares, hashed_decision, writing_file)
        server.reset()

def extract_lines(filename):
    lines = read_file(filename )

    results = []
    for line in lines:
        values = line.split(', ')
        first_entry = values[0].split('(')
        last_entry = values[2].split(')')

        results.append((int(first_entry[1]), float(values[1]), float(last_entry[0])))
    
    return results

def test_access_flow(threshold, access_policies, attribute_set, file_to_encrypt, counts):
    owners, ops = create_owner_list(threshold)
    server = Server()
    database_name = "test"

    key_reconstruction = extract_lines("results/key_reconstruct.txt")
    signature_reconstruction = extract_lines("results/sig_reconstruct.txt")
    
    for i in range(len(owners)):
        event_file = "results/simulation_disagree/test2_discrete_events_{}".format(owners[i])
        message_file = "results/simulation_disagree/test2_message_complexity_{}".format(owners[i])

        f = open(event_file, "w+")
        f.close()

        f = open(message_file, "w+")
        f.close()

        key_lbound, key_ubound = calc_gap(key_reconstruction[i])
        sig_lbound, sig_ubound = calc_gap(signature_reconstruction[i])

        lower_bound = key_lbound + sig_lbound
        upper_bound = key_ubound + sig_ubound

        owner_count = owners[i]
        ops_count = ops[i]
        owner_threshold = math.ceil(owner_count * threshold)

        levels_of_access = {owner_threshold: 1}
        print("levels of access", levels_of_access)

        param = {
            # RSA modulus length, in bits.
            # A toy value suitable for testing is, e.g., 100.
            # A more realistic value is, e.g., 3072
            'rsa_modulus_length_in_bits': 2048,
            # Number of signature shares needed to obtain a signature.
            # This is k in the paper.
            'number_parties_needed': owner_threshold,
            # Number of players engaging in the protocol. This is l in the paper.
            'number_parties_total': owner_count,
            # This is t in the paper. max k-1. Currently unused in this code.
            'number_parties_corrupted': 0,
            "e": 0x10001,
        }

        for j in counts:
            print("owner_count ", owner_count)
            print("ops_count ", ops_count)
            resource_id = uuid.uuid4()

            server.test_run(owner_count, ops_count, attribute_set, resource_id, levels_of_access, threshold, access_policies, param, file_to_encrypt, 1, database_name, lower_bound, upper_bound, event_file, message_file)
            server.reset()

count = list(range(1, 11))
#access_policy = ['access_policies/ruleset_6.json', 'access_policies/access_policy_5.json']
#attribute_set = ['Professor', 'CSE', 'Assignment', 'High', 'Weekday','Modify']
#file_to_encrypt = 'plaintexts/output_10_count_1.txt'
#test_access_flow(0.51, access_policy, attribute_set, file_to_encrypt, count)

#levels_of_access = {3: 1, 
#                    4: 2,
#                    5: 3,
#                    6: 4,
#                    7: 5,
#                    8: 6, 
#                    9: 7}
levels_of_access = {2:1}
#count = list(range(1, 11))
#byte_sizes = [10, 100, 1024, 16384, 53248, 131072, 262144, 525288, 1048576]
#benchmark_memory_encryption(count, byte_sizes, 3, 5, 3, True, 0.51, levels_of_access)
#benchmark_verify_shares(count, "times/verification/owner_verify", True, ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"], 'access_policies/ruleset_6.json', 'Accept', 0.51, levels_of_access, 0.51, memory=True)

#Because we need a threshold of half of the owners for the encryption key but 40% is high enough to go beyond the corrupted players
#benchmark_memory_reconstruction(0.51, 'Accept', 'access_policies/ruleset_6.json', ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"], 0.51)
#benchmark_set_up(count, levels_of_access, 0.51, 0.40)
#benchmark_verify_shares(count, "times/verification/operator_verify_process_time_1000000", False, ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"], 'access_policies/ruleset_6.json', 'Accept', 0.51, levels_of_access, 0.51, memory=False)
#benchmark_verify_shares(count, "times/verification/operator_verify_time_100", False, ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"], ['access_policies/ruleset_6.json'], 'Accept', 0.51, levels_of_access, 0.51, memory=False)
#benchmark_reconstruction(levels_of_access, 'Accept', 0.51, 0.51, 'access_policies/ruleset_6.json', ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"], key_reconstruct=True)
#access_json = "access_policies/test.json"
#make_access_policy(4, 3, 5, 5, 10, access_json)
#no_attributes = [5, 10, 15, 20, 25, 30]
#no_rules = [3, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
#no_rules = 50
#no_values = 7
#value_length = [3, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
#value_length = 7
#no_values = [3, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
#value_length = list(range(3, 71))
#attribute_value = 7
#no_attributes = 5
no_attributes = [3, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
#no_attributes = [100]

#every_tenth = list(range(5, 76))
#every_tenth = list(range(5, 201))
#value_length = every_tenth[0::5]

#for value in no_attributes:
#    for i in count:
#        make_access_policy(value, no_rules, no_values, attribute_value, value_length, "access_policies/attributes/no_attributes_{}_{}.json".format(value, i))
benchmark_policy("access_policies/values/no_values", no_attributes, count, 3, 5, 'test', 'times/policies/values_size', True, 5, 0.51, levels_of_access)
#benchmark_policy("access_policies/rules/no_rules", no_attributes, count, 3, 5, 'test', 'times/policies/rules_size', True, 5, 0.51, levels_of_access)

#server = Server()
#access_leader_id, encryption_leader_id, worker_ids, owner_ids, tkm_id = server.set_up_system(3, 5, 'test', 0.51, levels_of_access)
#result, heigth, size = server.test_generating_tree('access_policies/ruleset_6.json', owner_ids[0], size=True)