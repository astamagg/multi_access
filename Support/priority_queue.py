from itertools import count
import heapq
from queue import PriorityQueue
import random
import sys
sys.setrecursionlimit(1000000)

#Using priority queue is apparently not great, need to look into it
class PQ:
    def __init__(self):
        self.pq = PriorityQueue()
        self.entry_finder = {}
        self.REMOVED = '<removed-task>'
        self.counter = count()
        self.current_times = dict()
        self.message_count = 0

    def add_task(self, task, priority = 0):
        delay = random.randint(3, 10)
        priority = priority + delay
        print("SENDER: ", task[2])
        print("task: {}".format(task))
        receiver = task[1].id
        print("RECEIVER: ", receiver)
        sender = task[2]

        for i in range(self.pq.qsize()):
            curr_entry = self.pq.queue[i]
            curr_receiver = curr_entry[2][1].id
            curr_sender = curr_entry[2][2]

            if curr_sender == sender and curr_receiver == receiver and priority < curr_entry[0]:
                priority = curr_entry[0] + 1

        count = next(self.counter)
        self.message_count += 1
        self.pq.put((priority, count, task))

    def append_to_queue(self, task, time):
        self.add_task(task, time)
        self.check_queue()

    def check_queue(self):
        print("length of queue: ", self.pq.qsize())
        priority, count, task = self.pq.get()
        receiver_id = task[1].id

        if receiver_id in self.current_times:
            last_time = self.current_times[receiver_id]
            if last_time == priority:
                priority = priority + 1
        
        self.current_times[receiver_id] = priority

        task[1].receive_message(task[0], task[2], task[3], priority)

