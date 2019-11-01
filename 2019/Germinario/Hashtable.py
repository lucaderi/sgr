class Hashtable():
    def __init__(self, size):
        self.size = size
        self.hashmap = [[] for i in range(size)]

    def insert(self, key, value):
        hash_key = hash(key) % len(self.hashmap)
        key_exists = False
        bucket = self.hashmap[hash_key]    
        for i, kv in enumerate(bucket):
            k, v = kv
            if key == k:
                key_exists = True 
                break
        if key_exists:
            bucket[i] = ((key, value))
        else:
            bucket.append((key, value))

    def search(self, key):
        hash_key = hash(key) % len(self.hashmap)    
        bucket = self.hashmap[hash_key]
        for i, kv in enumerate(bucket):
            k, v = kv
            if key == k:
                return v

    def print_table(self):
        print self.hashmap
