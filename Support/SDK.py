from Support.blockchain import Channel

class SDK:
    def __init__(self, ledger):
        self.channel = ledger
        
    def set_op_operator(self, operators):
        self.operators = operators

    def access_request(self, resource_id, requester_id, attribute_set, start_time = 0):
        endorsement_policy = self.channel.endorsment_policy
        endorsing_peers = endorsement_policy['endorsing_peers']
        curr_time = start_time
        for peer in endorsing_peers:
            operator = self.operators[peer]
            curr_time += 1
            #operator.access_request(attribute_set, resource_id, requester_id, start_time)
            operator.receive_message("access_request", None, [attribute_set, resource_id, requester_id], curr_time)

    def smart_contract(self, resource_id):
        #Under the assumption that we only create one storage transaction per resource
        # NEED TO FINISH THE STORING ON THE CHAIN
        chain = self.channel.get_chain()
        for block in chain:
            for transaction in block['transactions']:
                if transaction['resource_id'] == str(resource_id):
                    if transaction['type'] == 'storage':
                        return transaction['ownerlist']

    def access_transaction(self, resource_id, recipient, decision, owner_signature, endorser_signature):
        self.channel.new_access_transaction(resource_id, recipient, decision, owner_signature)