#import LeaderOperators
from Support.util import Shares
from Support.SDK import SDK
import math
from queue import Queue
import uuid

#class AccessLeader(object):
class AccessLeader:
    # TODO Need to define how levels of access are defined for the operators
    def __init__(self, id, channel, owner_threshold, pq, levels_of_access):
        self.accepts = 0
        self.denies = 0
        self.id = id
        self.levels_of_access = levels_of_access
        self.operators = {}
        self.n_owners = None
        self.sig_params = None
        self.sig_pk = None
        self.SDK = SDK(channel)
        self.owner_threshold = owner_threshold
        self.STATUS = "free"
        self.pq = pq
        self.message_queue = Queue()
        self.responses = {}

    def receive_message(self, message_type, sender, arguments, start_time):
        self.message_queue.put((message_type, sender, arguments, start_time))
        self.check_queue()

    def check_queue(self):
        next_task = self.message_queue.get()
        message_type = next_task[0]
        processed = False
        if message_type == "access_request":
            processed = True
            self.access_request(next_task[2][0], next_task[2][1], next_task[2][2], next_task[3])
        if message_type == "receive_access_decision" and self.STATUS == "processing_request":
            processed = True
            self.receive_access_decision(next_task[2][0], next_task[2][1], next_task[1], next_task[3])
        if message_type == "final_decision":
            processed = True
            self.receive_final_decision_response(next_task[1], next_task[2][0], next_task[3])
        
        if not processed:
            self.pq.check_queue()

    def receive_final_decision_response(self, sender, agreed, start_time):
        if agreed:
            self.in_agreement += 1
            if self.in_agreement == (len(self.operators.keys()) - 2) :
                self.STATUS == "finalized"
                encryption_operator = self.operators[self.encryption_leader]
                self.pq.append_to_queue([ "access_decision", encryption_operator, self.id, [self.decision, self.level]], start_time+1)
            else:
                # TODO add failure to compute or plan some kind of typeout
                self.pq.check_queue()
        else:
            operator = self.operators[sender]
            self.pq.add_task(["verify_decision", operator, self.id, [self.responses[sender]]], start_time+11)
            self.pq.check_queue()

    def receive_signing_params(self, pk, params):
        self.sig_params = params
        self.sig_pk = pk

    def set_leaders(self, access_id, encryption_id):
        self.access_leader = access_id
        self.encryption_leader = encryption_id

    #TODO fix communication with the SDK
    def access_request(self, attribute_set, resource_id, requester_id, start_time):
        print("RESOURCE_ID: ", resource_id)
        self.STATUS = "processing_request"
        owner_list_str = self.SDK.smart_contract(resource_id)
        owner_list = [uuid.UUID(owner) for owner in owner_list_str]
        self.n_owners = len(owner_list)
        self.threshold_of_owners = math.ceil(len(owner_list) * self.owner_threshold)

        worker_operators = self.operators.copy()
        worker_operators.pop(self.access_leader)
        worker_operators.pop(self.encryption_leader)

        offsets = self.split_owners(len(owner_list), len(worker_operators.keys()))
        for i, operator in enumerate(worker_operators.values()):
            if len(offsets) == 1 or i == 0:
                curr_owner_list = owner_list[:offsets[0]]
            elif i == (len(worker_operators.values())-1):
                curr_owner_list = owner_list[offsets[i]:]
            else:
               curr_owner_list = owner_list[offsets[i-1]: offsets[i]]
            curr_owners = {x:self.owners[x] for x in curr_owner_list}
            self.pq.add_task(("receive_access_request", operator, self.id, (attribute_set, requester_id, resource_id, curr_owners)), start_time+1)
        self.pq.check_queue()

    def receive_participants(self, operators, owners):
        self.operators = operators
        self.SDK.set_op_operator(operators)
        self.owners = owners

    def split_owners(self, n_owner, n_operators):
        modulus = n_owner % n_operators
        split = n_owner // n_operators
        offsets = []

        curr_offset = 0
        if n_operators == 1:
            offsets.append(split)
        else:
            for i in range(n_operators):
                if i != (n_operators - 1):
                    curr_offset = split + curr_offset

                if modulus > 0:
                    curr_offset += 1
                    modulus = modulus - 1

                offsets.append(curr_offset)

        return offsets

    def calculate_current_status(self):
        thresholds = list(self.levels_of_access.keys())
        total_possible_accepts = self.n_owners - self.denies - self.accepts

        if (total_possible_accepts + self.accepts) <  thresholds[0] and (self.denies) >= thresholds[0]:
            return -1

        if len(thresholds) == 1:
            if self.accepts >= thresholds[0]:
                return self.levels_of_access.get(thresholds[0])
            else:
                return 0
        else:
            for i in range(len(thresholds)-1):
                if self.accepts >= thresholds[i] and total_possible_accepts <= thresholds[i+1]:
                    return self.levels_of_access.get(thresholds[i])
                else:
                    return 0
            
    def receive_access_decision(self, decision, owner, sender_id, start_time):
        print("receive access decisions ", sender_id)
        if decision == "Accept":
            self.accepts += 1
        else:
            self.denies += 1

        level = self.calculate_current_status()

        operator = self.operators[sender_id]
        if sender_id in self.responses:
            self.responses[sender_id] += 1
        else:
            self.responses[sender_id] = 1

        curr_time = start_time + 1
        self.pq.add_task(["acks", operator, self.id, [owner]], curr_time)

        total = self.accepts + self.denies

        print("level: ", level)

        if level > 0 and total >=  self.threshold_of_owners:
            self.send_final_decision("Accept", curr_time+1, level)
        elif level == -1:
            self.send_final_decision("Deny", curr_time+1)
        else:
            self.pq.check_queue()

    def send_final_decision(self, decision, time, level= None):
        self.STATUS = "reached_decision"
        self.decision = decision
        self.level = level
        self.in_agreement = 0
        workers = len(self.operators.keys()) - 2
        curr_time = time
        for i, key in enumerate(self.operators.keys()):
            if key != self.access_leader and key != self.encryption_leader:
                operator = self.operators[key]
                curr_time += 1
                if key in self.responses:
                    responses = self.responses[key]
                else:
                    responses = 0
                self.pq.add_task(["verify_decision", operator, self.id, [responses]], curr_time)
        self.pq.check_queue()