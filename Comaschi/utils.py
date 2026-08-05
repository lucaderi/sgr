import pyprctl

#MACRO CONDIVISE TRA ANALYZER E GUI
GLOBAL = "GLOBAL"
DEVICES = "DEVICES"
PERFORMANCE = "PERFORMANCE"
TRAFFIC = "TRAFFIC"
CLUSTERS = "CLUSTERS"
MAC_TABLE = "MAC_TABLE"

ROUND = "ROUND"
SESSION = "SESSION"

#PERFORMANCE
#Round
AVG_ROUND_DURATION = "AVG_ROUND_DURATION"
AVG_ROUND_QUEUE_SIZE = "AVG_ROUND_QUEUE_SIZE"
ROUND_PROCESSED_PKTS_PER_SEC = "ROUND_PROCESSED_PKTS_PER_SEC"
ROUND_PROCESSED_VOLUME_PER_SEC = "ROUND_PROCESSED_VOLUME_PER_SEC"
#Session
SESSION_AVG_ROUND_DURATION = "SESSION_AVG_ROUND_DURATION"
SESSION_AVG_QUEUE_SIZE = "SESSION_AVG_QUEUE_SIZE"
SESSION_PROCESSED_PKTS_PER_SEC = "SESSION_PROCESSED_PKTS_PER_SEC"
SESSION_PROCESSED_VOLUME_PER_SEC = "SESSION_PROCESSED_VOLUME_PER_SEC"

#TRAFFIC
#Round
ROUND_PKTS_PER_SEC = "ROUND_PKTS_PER_SEC"
ROUND_VOLUME_PER_SEC = "ROUND_VOLUME_PER_SEC"
PERC_ROUND_UNASSIGNED_PKTS = "PERC_ROUND_UNASSIGNED_PKTS"
PERC_ROUND_UNASSIGNED_VOLUME = "PERC_ROUND_UNASSIGNED_VOLUME"
#Session
SESSION_PKTS_PER_SEC = "SESSION_PKTS_PER_SEC"
SESSION_VOLUME_PER_SEC = "SESSION_VOLUME_PER_SEC"
PERC_SESSION_UNASSIGNED_PKTS = "PERC_SESSION_UNASSIGNED_PACKETS"
PERC_SESSION_UNASSIGNED_VOLUME = "PERC_SESSION_UNASSIGNED_VOLUME"

#CLUSTERS
NEAR_CLUSTER = "NEAR (5M)"
MEDIUM_CLUSTER = "MEDIUM (15M)"
FAR_CLUSTER = "FAR (30M)"
OUT_OF_RANGE_CLUSTER = "OUT OF RANGE (>30M)"

#GLOBAL 
TOTAL_DEV = "TOTAL DEVICES"
AP = "AP"
STA = "STA"
MESH = "MESH"
UNIDENTIFIED = "UNIDENTIFIED"
TOTAL_RANDOMIZED = "TOTAL RANDOMIZEDs"

class heap_dict:
    def __init__(self):
        self.__map = {} #key: heap_index
        self.__heap = list()

    def __heapify_up(self, elem_idx):
        while elem_idx > 0:
            parent_idx = (elem_idx - 1) // 2
            if self.__heap[parent_idx][1] > self.__heap[elem_idx][1]:
                #update dict
                self.__map[self.__heap[elem_idx][0]] = parent_idx
                self.__map[self.__heap[parent_idx][0]] = elem_idx
                #update heap
                self.__heap[elem_idx], self.__heap[parent_idx] = self.__heap[parent_idx], self.__heap[elem_idx]

                elem_idx = parent_idx
            else: break

    def __heapify_down(self, elem_idx):
        heap_len = len(self.__heap)
        while True:
            left_child_idx = (elem_idx*2) +1
            right_child_idx = left_child_idx +1
            minimum_idx = elem_idx
            if left_child_idx < heap_len and self.__heap[left_child_idx][1] < self.__heap[minimum_idx][1]:
                minimum_idx = left_child_idx
            if right_child_idx < heap_len and self.__heap[right_child_idx][1] < self.__heap[minimum_idx][1]:
                minimum_idx = right_child_idx
            if minimum_idx == elem_idx:
                break
            else:
                #update dict
                self.__map[self.__heap[elem_idx][0]] = minimum_idx
                self.__map[self.__heap[minimum_idx][0]] = elem_idx
                #update heap
                self.__heap[elem_idx], self.__heap[minimum_idx] = self.__heap[minimum_idx], self.__heap[elem_idx]

                elem_idx = minimum_idx

    def update(self, elem:tuple):
        key, value = elem
        if key in self.__map:
            idx = self.__map[key]
            self.__heap[idx] = (key, value)
            parent_idx = (idx-1) // 2
            if idx > 0 and self.__heap[parent_idx][1] > self.__heap[idx][1]:
                self.__heapify_up(idx)
            else:
                self.__heapify_down(idx)     
        else:
            self.__heap.append(elem)
            elem_idx = len(self.__heap) - 1
            self.__map[key] = elem_idx
            self.__heapify_up(elem_idx)

    def remove(self, key):
        if key not in self.__map:
            return None
        elem = self.__heap[self.__map[key]]
        elem_idx = self.__map.pop(key)
        heaplen = len(self.__heap)
        if elem_idx == heaplen - 1:
            return self.__heap.pop()
        else:
            last_elem_idx = heaplen - 1 
            self.__map[self.__heap[last_elem_idx][0]] = elem_idx
            self.__heap[elem_idx], self.__heap[last_elem_idx] = self.__heap[last_elem_idx], self.__heap[elem_idx]
            self.__heap.pop()
            parent_idx = (elem_idx-1) // 2
            if elem_idx > 0 and self.__heap[parent_idx][1] > self.__heap[elem_idx][1]:
                self.__heapify_up(elem_idx)
                return elem
            else:
                self.__heapify_down(elem_idx)
                return elem

    def remove_min(self):
        if len(self.__heap) == 0:
            return None
        else:
            key_to_remove = self.__heap[0][0]
            return self.remove(key_to_remove)



if __name__ == '__main__':
    pass
    
    



    
        

    
        

        