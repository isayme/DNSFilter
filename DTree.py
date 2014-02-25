import re

class DNode:
    def __init__(self, value = None):
        self.__value = value
        self.__flag = False

        self.__key = {}
        for i in ".*abcdefghijklmnopqrstuvwxyz-0123456789":
            self.__key[i] = None

    def getValue(self):
        return self.__value
    
    def getKeys(self):
        return self.__key
    
    def getKey(self, key):
        return self.__key[key]
    
    def setKey(self, key, node):
        self.__key[key] = node

    def setFlag(self, flag):
        self.__flag = flag
        
    def getFlag(self):
        return self.__flag

class DTree():
    def __init__(self):
        self.__head = DNode()

        # regex for domain
        self.__pattern = re.compile(r"^(([0-9a-z][0-9a-z-]{0,62}|\*)\.)+([0-9a-z][0-9a-z-]{0,62})$")
    
    def addDomain(self, domain):
        #print "Add domain :", domain
        domain = domain.lower()
        if None == self.__pattern.match(domain):
            print "Not valid domain [%s]" % domain
            return False
        
        # reverse, for wildcard
        domain = domain[::-1]

        dlen = len(domain)

        cur = self.__head
        for i in range(0, dlen):
            if None == cur.getKey(domain[i]):
                #print "New node for ", domain[i]
                newnode = DNode(domain[i])
                cur.setKey(domain[i], newnode)
            #else:
                #print "exist ", domain[i]
            cur = cur.getKey(domain[i])
                
        cur.setFlag(True)
    
    def searchDomain(self, domain):
        #print "Search domain :", domain
        dlen = len(domain)
        if 1 >= dlen:
            print "domain length is 0"
            return False
        
        domain = domain.lower()
        #if None == self.__pattern.match(domain):
        #    print "Not valid domain [%s]" % domain
        #    return False
        
        # reverse, for wildcard
        domain = domain[::-1]
        
        cur = self.__head
        for i in range(0, dlen):
            if '.' == cur.getValue() and None != cur.getKey('*'):
                #print "Wildchar match!"
                return True
                
            if None == cur.getKey(domain[i]):
                #print "No node for (%d:%c)" % (i, domain[i])
                return False

            cur = cur.getKey(domain[i])    

        return cur.getFlag()

    def printDomains(self, node = None, prefix = ""):
        if None == node:
            node = self.__head
        cur = node

        keys = cur.getKeys()
        for item in keys:
            if None == keys[item]:
                #print "keys[%s] is None" % item
                continue
            if True == keys[item].getFlag():
                # reverse print
                print (prefix + item)[::-1]
                
            self.printDomains(keys[item], prefix + item)
        
if __name__ == '__main__':
    tree = DTree()

    tree.addDomain("W-w.abc.com")
    tree.addDomain("Ww.abc.cn")
    tree.addDomain("www.facebook.com")
    tree.addDomain("*.facebook.com")

    #print tree.searchDomain("wxxx.abc.com")
    print tree.searchDomain("www.facebook.com")


    
    
        

