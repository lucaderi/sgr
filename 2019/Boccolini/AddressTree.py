import Address
from Address import *

class AddressTree():

    def __init__(self):
        self.head = None

    def add(self,new_node):
        if self.head is None:
            self.head = new_node
        else:
            self.head.add_child(new_node)

    def __str__(self):
        return self.head.__str__()

    def __len__(self):
        if self.head is None:
            return 0
        else:
            return self.head.__len__()

    def getAddresses(self):
        if self.head is None:
            return []
        else:
            return self.head.getAddress()
