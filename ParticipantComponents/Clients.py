from Support.SDK import SDK

class Client:
    def __init__(self, channel, attribute_set, id):
        self.SDK = SDK(channel)
        self.attributes = attribute_set
        self.id = id

    def request_access(self, resource_id, start_time = 0):
        self.SDK.access_request(resource_id, self.id, self.attributes, start_time)