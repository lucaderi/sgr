class Address():

    def __init__(self,address,port,protocol):
        try:
            self.byte1,self.byte2,self.byte3,self.byte4 = address.split('.',-1)
        except:
            self.byte1, self.byte2, self.byte3, self.byte4 = '0','0','0','0'
            print ("Address must be x.y.z.w ")
        self.ports = [port]
        self.right = None
        self.left = None
        self.protocol = protocol

    def add_port(self,p):
        if not self.ports.__contains__(p):
            self.ports.append(p)

    def getProtocol(self):
        return self.protocol

    def compareTo(self,addr):
        b1,b2,b3,b4 = addr.getBytes()
        if self.byte1 > b1:
            return 1
        elif self.byte1 < b1:
            return -1
        else:
            if self.byte2 > b2:
                return 1
            elif self.byte2 < b2:
                return -1
            else:
                if self.byte3 > b3:
                    return 1
                elif self.byte3 < b3:
                    return -1
                else:
                    if self.byte4 > b4:
                        return 1
                    elif self.byte4 < b4:
                        return -1
                    else:
                        if self.protocol==addr.protocol:
                            return 0
                        else:
                            return -1

    def getBytes(self):
        return self.byte1,self.byte2,self.byte3,self.byte4

    def getAddr(self):
        return str(self.byte1)+'.'+str(self.byte2)+'.'+str(self.byte3)+'.'+self.byte4

    def getPorts(self):
        return self.ports

    def add_child(self,child):
        compare = self.compareTo(child)
        if compare == 0:
            for p in child.getPorts():
                self.add_port(p)
        elif compare == 1:
            if self.left is None:
                self.left = child
                return
            else:
                self.left.add_child(child)
                return
        else:
            if self.right is None:
                self.right = child
                return
            else:
                self.right.add_child(child)
                return

    def __str__(self):
        pts = '/'
        for p in self.ports:
            if pts.__len__()>1:
                pts = pts+"-"
            pts = pts+str(p)
        if self.left is None:
            l = ''
        else:
            l = self.left.__str__()+" || "

        if self.right is None:
            r = ''
        else:
            r = " || "+self.right.__str__()

        return l+"\n"+self.byte1+"."+self.byte2+"."+self.byte3+"."+self.byte4+pts+"\n"+r

    def __len__(self):
        c = 0
        if not (self.left is None):
            c += self.left.__len__()
        if not (self.right is None):
            c += self.right.__len__()

        return c+(self.ports.__len__())

    def getAddress(self):
        l = []
        if not(self.left is None):
            l.extend(self.left.getAddress())
        l.append((self.getAddr(),self.ports,self.protocol))
        if not(self.right is None):
            l.extend(self.right.getAddress())
        return l