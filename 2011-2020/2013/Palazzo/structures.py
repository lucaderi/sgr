#!/usr/bin/python
# -*- coding: utf-8 -*-

class Node_trie(object):
    def __init__(self, pref=None, dat=None):
        """Initialize trie node"""
        self.child = [None,None]
        self.prefix = pref
        self.data = dat
        self.others_are_none = 0

    def __eq__(self, other):
        """Comparet two trie node"""
        if (self.prefix == other.prefix):
            if ((self.data is None) and (other.data is None)) or (not(self.data is None) and not(other.data is None)):
                if (self.child[0] is None) and (other.child[0] is None):
                    if (self.child[1] is None) and (other.child[1] is None):
                        return True
                    elif not(self.child[1] is None) and not(other.child[1] is None):
                        return True
                    else:
                        return False
                elif not(self.child[0] is None) and not(other.child[0] is None):
                    if (self.child[1] is None) and (other.child[1] is None):
                        return True
                    elif not(self.child[1] is None) and not(other.child[1] is None):
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            return False
#return self.__dict__ == other.__dict__

    def set_order(self, kind_of_order):
        """Specify what information in the filter must be considered"""
        self.others_are_none = 0            
        self.order = kind_of_order

    @classmethod
    def print_all(self):
        if not(self.data is None):
            print self.data
        if not(self.child[0] is None):
            self.child[0].print_all()
        if not(self.child[1] is None):
            self.child[1].print_all()
        return 1


class Trie(object):
    def __init__(self, kind_of_order):
        """Initialize trie, order takes 'destination_ip' or 'sender_ip' values"""
        self.root = None
        self.order = kind_of_order

    def create_Leaf(self, v, u, indexl, i, element, d):
        """Create a leaf in trie, with data equals to element"""
        if not(v == u):
            el = int((element[d])[indexl])
            v.child[ el ] = Node_trie()
            v = v.child[ el ]
            v.prefix = (element[d], i)
            p,j = u.prefix
            v.child[ int(p[i]) ] = u
            u = v
        
        el = int((element[d])[i])
        u.child[ el ] = Node_trie()
        u = u.child[ el ]
        u.prefix = (element[d],len(element[d]))
        u.data = element
        if self.order == 'destination_ip':
            u.tree_ips = Trie("sender_ip")
            if element[3] is None:
                u.others_are_none = 1
            else:
                u.tree_ips.insert_list_simple(element)
        else:
            u.others_are_none = 1

    def create_Intermediate_Leaf(self, v, u, indexl, i, element, d):
        """Create a new node, isn't a leaf but it contains data equivalents to element"""
        s = Node_trie()
        s.prefix = (element[d], len(element[d]))
        s.data = element
        if self.order == 'destination_ip':
            s.tree_ips = Trie("sender_ip")
            if element[3] is None:
                s.others_are_none = 1
            else:                
                s.tree_ips.insert_list_simple(element)
        else:
            s.others_are_none = 1
        
        p,j = u.prefix
        s.child[ int(p[i]) ] = u
        v.child[ int(p[indexl]) ] = s

    def insert(self, element):
        """Insert a node in a trie, if there's another node with data equivalets to element any node will be inserted"""
        if self.root is None:
            self.root = Node_trie()        
        u = self.root
        if self.order == 'destination_ip':
            d = 1
        else:
            d = 3
        
        m = len(element[d])
        end = False
        i = 0
        while (not(end) and i<m):
            v = u
            indexl = i
            el = int((element[d])[i])
            if not(u.child[ el ] is None):
                u = u.child[ el ]
                p,j = u.prefix
                while (i<m and i<j and p[i]==(element[d])[i]):
                    i = i + 1
                end = (i<m) and (i<j)
            else:
                end = True
        
        if (end == True):#any node, in trie, has data equals to element
            self.create_Leaf(v,u,indexl,i,element,d)
        elif (i==m and not(end) and i<j):#element is contained, not equal, in another node's data
            self.create_Intermediate_Leaf(v,u,indexl,i,element,d)
        elif (i==m and not(end) and i==j):#element is equal to node's prefix
            if u.data is None:
                u.data = element
                if self.order == 'destination_ip':
                    u.tree_ips = Trie("sender_ip")
            if self.order == 'destination_ip':
                if element[3] is None:
                    u.others_are_none = 1
                else:
                    u.tree_ips.insert_list_simple(element)
            else:
                u.others_are_none = 1
        
        else:
            pass
        return self.root

    def search(self, element):
        """Search element in trie"""
        if self.root is None:
            return False
        else:
            u = self.root
            if self.order == 'destination_ip':
                d = 1
            else:
                d = 3
            end = False
            i = 0
            m = len(element[d])
            while (not(end) and i<m):
                #print "entro %d %d"% (i,d)
                el = int((element[d])[i])
                if not(u.child[ el ] is None):
                    u = u.child[ el ]
                    p,j = u.prefix
                    #print p,j,d
                    while (i<m and i<j and p[i]==(element[d])[i]):
                        i = i + 1
                        #print i
                    if i==j and not(u.data is None):#element's ip is contained, or is equals, to data of node
                        if self.order == 'destination_ip':
                            if u.others_are_none == 1:
                                return True
                            else:
                                if u.tree_ips.search(element) == True:
                                    #print "return t %d"% d
                                    return True
                        else:
                            #print "return t %d"% d
                            return True
                    
                    end = (i<m) and (i<j)
                else:
                    end = True#there isn't any node with data equals to element
            
            return False


    def print_all(self, node, i):
        data = ''
        if self.order == 'destination_ip':
            d = 1
        else:
            d = 3
        if not(node.data is None):
            data += node.data[d] + " %d %d "% (i,d)
            if d == 1:
                data += node.tree_ips.print_all_elements() + '///////'
        if not(node.child[0] is None):
            data += self.print_all(node.child[0], i+1)
        if not(node.child[1] is None):
            data += self.print_all(node.child[1], i+1)
        return data
    
    def print_all_elements(self):
        if self.root is None:
            return "No Element"
        else:
            #return self.root.print_all()
            return self.print_all(self.root, 1)

    def convert_ip(self, element):#element is a tuple (that is a filter)
        """Convert tuple's ip address to bit notation; if there's subnet mask, returns only bit specified in mask"""
        if not(element[1] is None):
            s = element[1].find('/')
            if s != -1:
                s = element[1].split('/')
                k = s[0].split('.', 3)
                g = (bin(int(k[0]))[2:]).zfill(8) + (bin(int(k[1]))[2:]).zfill(8) + (bin(int(k[2]))[2:]).zfill(8) + (bin(int(k[3]))[2:]).zfill(8)
                final1 = g[:int(s[1])]
            else:
                k = element[1].split('.', 3)
                final1 = (bin(int(k[0]))[2:]).zfill(8) + (bin(int(k[1]))[2:]).zfill(8) + (bin(int(k[2]))[2:]).zfill(8) + (bin(int(k[3]))[2:]).zfill(8)
            #print "in convert_ip dest =" + final1
        else:
            final1 = None
        
        if not(element[3] is None):
            s = element[3].find('/')
            if s != -1:
                s = element[3].split('/')
                k = s[0].split('.', 3)
                g = (bin(int(k[0]))[2:]).zfill(8) + (bin(int(k[1]))[2:]).zfill(8) + (bin(int(k[2]))[2:]).zfill(8) + (bin(int(k[3]))[2:]).zfill(8)
                final2 = g[:int(s[1])]
            else:
                k = element[3].split('.', 3)
                final2 = (bin(int(k[0]))[2:]).zfill(8) + (bin(int(k[1]))[2:]).zfill(8) + (bin(int(k[2]))[2:]).zfill(8) + (bin(int(k[3]))[2:]).zfill(8)
            #print "in convert_ip mitt=" + final2
        else:
             final2 = None
        
        data = (element[0],final1,element[2],final2,element[4])
        return data

    
    def insert_list_simple(self, *args):
        """Insertion in trie without converting ip address of tuples (args) in bit notation"""
        for element in args:
            self.insert(element)

    def insert_list(self, *args):
        """Insertion in trie, including conversion of ip address"""
        for element in args:
            new_element = self.convert_ip(element)
            self.insert(new_element)

    def search_pkt(self, pkt):
        """Search packet in trie, including conversion of packet's ip address"""
        new_element = self.convert_ip(pkt)
        return self.search(new_element)


class Node_avl(object):
    def __init__(self, data, left=None, right=None):
        """Initialize AVL Node"""
        self.data = data
        self.left = left
        self.right = right
        self.height = 1

    def __repr__(self):
        return "<AVL Node: %s %s>" % (self.data, self.order)

    def recursive_repr(self, space=0):
        data = '\n' + self.__repr__()
        trees = ''
        if self.order == 'protocol':
            tree1 = '\n' + ('-' * (space + 2)) + ('%d'% self.tree_pd.height) + ' Dest_port tree ' + self.tree_pd.__repr__()
            tree2 = '\n' + ('-' * (space + 2)) + ('%d'% self.tree_ps.height) + ' Send_port tree ' + self.tree_ps.__repr__()
            tree3 = '\n' + ('-' * (space + 2)) + ' Dest_ip tree ' + self.tree_ipd.print_all_elements()
            tree4 = '\n' + ('-' * (space + 2)) + ' Send_ip tree ' + self.tree_ips.print_all_elements()
            trees = tree1 + tree2 + tree3 + tree4 + '\n' + ('-' * (space + 3 ))
        
        elif self.order == 'destination_port':
            tree2 = '\n' + ('-' * (space + 2)) + ('%d'% self.tree_ps.height) + ' Send_port tree ' + self.tree_ps.__repr__()
            tree3 = '\n' + ('-' * (space + 2)) + ' Dest_ip tree ' + self.tree_ipd.print_all_elements()
            tree4 = '\n' + ('-' * (space + 2)) + ' Send_ip tree ' + self.tree_ips.print_all_elements()
            trees = tree2 + tree3 + tree4 + '\n' + ('-' * (space + 3 ))
        
        elif self.order == 'sender_port':
            tree3 = '\n' + ('-' * (space + 2)) + ' Dest_ip tree ' + self.tree_ipd.print_all_elements()
            tree4 = '\n' + ('-' * (space + 2)) + ' Send_ip tree ' + self.tree_ips.print_all_elements()
            trees = tree3 + tree4 + '\n' + ('-' * (space + 3 ))
        
        elif self.order == 'destination_ip':
            tree4 = '\n' + ('-' * (space + 2)) + ' Send_ip tree ' + self.tree_ips.print_all_elements()
            trees = tree4 + '\n' + ('-' * (space + 3 ))
        
        else:
            trees = ''
            
        data += trees
        if not(self.left is None):
            data += '\n' + ('-' * (space + 2)) + ' Left: ' + self.left.recursive_repr(space + 2)
        
        if not(self.right is None):
            data += '\n' + ('-' * (space + 2)) + ' Right: ' + self.right.recursive_repr(space + 2)
        
        return data
    

    def set_order(self, kind_of_order):
        """Specify what information, in the filter, must be considered"""
        self.others_are_none = 0            
        self.order = kind_of_order


    def compare_protocol_or_port(self, element, index):
        """Compare protocol or port between the current node and element (tuple)"""
        if element[index] is None:
            if self.data[index] is None:
                return '='
            else:
                return '<'
        else:
            if self.data[index] is None:
                return '>'
            else:
                if element[index] < self.data[index]:
                    return '<'
                elif element[index] > self.data[index]:
                    return '>'
                else:
                    return '='
    #this function returns: '>' if element[index] > node's data, '<' if element[index] < node's data, '=' if element[index] = node's data

    def compare(self, element):
        if self.order == 'protocol':
            return self.compare_protocol_or_port(element,0)
        elif self.order == 'destination_port':
            return self.compare_protocol_or_port(element,2)
        elif self.order == 'sender_port':
            return self.compare_protocol_or_port(element,4)
        else:
            pass

    def create_trees(self):
        """Create trees in a node"""
        #when a new node is just inserted, will be created new trees used to insert datas of tuple (filter) considering the node's order
        if self.order == 'protocol':
            self.tree_pd = AVL("destination_port")
            self.tree_ps = AVL("sender_port")
            self.tree_ipd = Trie("destination_ip")
            self.tree_ips = Trie("sender_ip")
            if ( self.data[1] is None ) and ( self.data[2] is None ) and ( self.data[3] is None ) and ( self.data[4] is None ):
                self.others_are_none = 1
            else:
                if not(self.data[2] is None):
                    self.tree_pd.insert_list(self.data)
                
                elif not(self.data[4] is None):
                    self.tree_ps.insert_list(self.data)
                
                elif not(self.data[1] is None):
                    self.tree_ipd.insert_list(self.data)
                
                elif not(self.data[3] is None):
                    self.tree_ips.insert_list(self.data)
                
                else:
                    pass
        
        elif self.order == 'destination_port':
            self.tree_ps = AVL("sender_port")
            self.tree_ipd = Trie("destination_ip")
            self.tree_ips = Trie("sender_ip")
            if ( self.data[1] is None ) and ( self.data[3] is None ) and ( self.data[4] is None ):
                self.others_are_none = 1
            else:
                if not(self.data[4] is None):
                    self.tree_ps.insert_list(self.data)
                
                elif not(self.data[1] is None):
                    self.tree_ipd.insert_list(self.data)
                    
                elif not(self.data[3] is None):
                    self.tree_ips.insert_list(self.data)
                
                else:
                    pass
        
        elif self.order == 'sender_port':
            self.tree_ipd = Trie("destination_ip")
            self.tree_ips = Trie("sender_ip")
            if ( self.data[1] is None ) and ( self.data[3] is None ):
                self.others_are_none = 1
            else:
                if not(self.data[1] is None):
                    self.tree_ipd.insert_list(self.data)
                
                elif not(self.data[3] is None):
                    self.tree_ips.insert_list(self.data)
                
                else:
                    pass        
        
        else:
            pass


class AVL(object):
    def __init__(self, kind_of_order, root=None):
        """Initialize AVL"""
        #order specifies on which tuple's information doing comparison between AVL's node
        self.root = root
        self.order = kind_of_order

    def insert(self, node, element):
        """Insert new node in AVL; if there's a node with data equals to element, insertion will be done on one of trees node"""
        if node is None:
            node = Node_avl(element)
            node.set_order(self.order) #in this case, order can be 'protocol',
            node.create_trees()        # 'destination_port' or 'sender_port'
            return node
        
        result = node.compare(element)
        #node.data > element:
        if result == '<':
            node.left = self.insert(node.left,element)
            if (self.node_height(node.left) - self.node_height(node.right)) == 2:
                if node.left.compare(element) == '>':
                #element > node.left.data:
                    node.left = self.Counterclockwise(node.left)
                node = self.Clockwise(node)
        
        #node.data < element:
        elif result == '>':
            node.right = self.insert(node.right,element)
            if (self.node_height(node.right) - self.node_height(node.left)) == 2:
                if node.right.compare(element) == '<':
                #element < node.right.data:
                    node.right = self.Clockwise(node.right)
                node = self.Counterclockwise(node)
        
        else:
            #filter (tuple) has the same value of node
            #so filter's information will be inserted in one of these trees
            if self.order == 'protocol':
                if not(element[2] is None):
                    node.tree_pd.insert_list(element)
                elif not(element[4] is None):
                    node.tree_ps.insert_list(element)
                elif not(element[1] is None):
                    node.tree_ipd.insert_list(element)
                elif not(element[3] is None):
                    node.tree_ips.insert_list(element)
                else:
                    node.others_are_none = 1
            
            elif self.order == 'destination_port':
                if not(element[4] is None):
                    node.tree_ps.insert_list(element)
                elif not(element[1] is None):
                    node.tree_ipd.insert_list(element)
                elif not(element[3] is None):
                    node.tree_ips.insert_list(element)
                else:
                    node.others_are_none = 1
            
            elif self.order == 'sender_port':
                if not(element[1] is None):
                    node.tree_ipd.insert_list(element)
                elif not(element[3] is None):
                    node.tree_ips.insert_list(element)
                else:
                    node.others_are_none = 1
            
            else:
                pass
            return node
        
        node.height = max(self.node_height(node.left), self.node_height(node.right)) + 1
        return node

    
    def Clockwise(self, node):
        """Clockwise rotation on AVL"""
        other_node = node.left
        node.left = other_node.right
        other_node.right = node
        node.height = max(self.node_height(node.left), self.node_height(node.right)) + 1
        other_node.height = max(self.node_height(other_node.left), self.node_height(other_node.right)) + 1
        return other_node
        
    def Counterclockwise(self, node):
        """Counterclockwise rotation on AVL"""
        other_node = node.right
        node.right = other_node.left
        other_node.left = node
        node.height = max(self.node_height(node.left), self.node_height(node.right)) + 1
        other_node.height = max(self.node_height(other_node.left), self.node_height(other_node.right)) + 1
        return other_node

    def node_height(self, node):
        if node is None:
            return 0
        else:
            return node.height

    @property
    def height(self):
        if self.root is None:
            return 0
        else:
            return self.root.height
    
    def search(self, node, element):
        """Search element in AVL"""
        if node is None:
            return False
        else:
            if self.order == 'protocol':
                result = node.compare(element)
                if result == '>':
                    return self.search(node.right, element)
                
                elif result == '<':
                    return self.search(node.left, element)
                
                else:
                    if node.others_are_none == 1:
                        return True
                    else:
                        result = node.tree_pd.search_tree(element)
                        if result == True:
                            return True
                        else:
                            result = node.tree_ps.search_tree(element)
                            if result == True:
                                return True
                            else:
                                result = node.tree_ipd.search_pkt(element)
                                if result == True:
                                    return True
                                else:
                                    return node.tree_ips.search_pkt(element)
                    
            elif self.order == 'destination_port':
                result = node.compare(element)
                if result == '>':
                    return self.search(node.right,element)
                elif result == '<':
                    return self.search(node.left,element)
                else:
                    if node.others_are_none == 1:
                        return True
                    else:
                        result = node.tree_ps.search_tree(element)
                        if result == True:
                            return True
                        else:
                            result = node.tree_ipd.search_pkt(element)
                            if result == True:
                                return True
                            else:
                                return node.tree_ips.search_pkt(element)
            
            elif self.order == 'sender_port':
                result = node.compare(element)
                if result == '>':
                    return self.search(node.right, element)
                elif result == '<':
                    return self.search(node.left, element)
                else:
                    if node.others_are_none == 1:
                        return True
                    else:
                        result = node.tree_ipd.search_pkt(element)
                        if result == True:
                            return True
                        else:
                            return node.tree_ips.search_pkt(element)
            
            else:
                pass


    def __repr__(self):
        if self.root is None:
            return "<Empty AVL %s >"% self.order
        else:
            return ('%d'% self.height) + self.root.recursive_repr()

    def insert_list(self, *elements):#elements are filters
        for element in elements:
            self.root = self.insert(self.root, element)

    def search_tree(self, element):#element is a packet
        if self.root is None:
            return False
        else:
            return self.search(self.root,element)


class Main_Structures(object):
    def __init__(self):
        """Initialize main structures"""
        self.prot_tree = AVL('protocol')
        self.portdest_tree = AVL('destination_port')
        self.portsend_tree = AVL('sender_port')
        self.ipdest_tree = Trie('destination_ip')
        self.ipsend_tree = Trie('sender_ip')

    def insert(self, *elements):#elements is a filters list
        for element in elements:
            if not(element[0] is None):
                self.prot_tree.insert_list(element)
            else:
                if not(element[2] is None):
                    self.portdest_tree.insert_list(element)
                else:
                    if not(element[4] is None):
                        self.portsend_tree.insert_list(element)
                    else:
                        if not(element[1] is None):
                            self.ipdest_tree.insert_list(element)
                        else:
                            self.ipsend_tree.insert_list(element)

    def search(self, *pkts):
        for pkt in pkts:
            if self.prot_tree.search_tree(pkt):
                return "Satisfied a filter prot"
            else:
                if self.portdest_tree.search_tree(pkt):
                    return "Satisfied a filter portdest"
                else:
                    if self.portsend_tree.search_tree(pkt):
                        return "Satisfied a filter portsend"
                    else:
                        if self.ipdest_tree.search_pkt(pkt):
                            return "Satisfied a filter ipdest"
                        else:
                            if self.ipsend_tree.search_pkt(pkt):
                                return "Satisfied a filter ipsend"
                            else:
                                return "Any filter has been satisfied"

    def __repr__(self):
        data = ''
        data += 'MAIN TREE' + self.prot_tree.__repr__()
        data += '\n MAIN TREE'
        data += self.portdest_tree.__repr__()
        data += '\n MAIN TREE'
        data += self.portsend_tree.__repr__()
        data += '\n MAIN TREE'
        data += self.ipdest_tree.print_all_elements()
        data += '\n MAIN TREE'
        data += self.ipsend_tree.print_all_elements()
        return data

