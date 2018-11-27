import queue
import threading
import re


## wrapper class for a queue of packets
class Interface:
    ## @param maxsize - the maximum size of the queue storing packets
    def __init__(self, maxsize=0):
        self.in_queue = queue.Queue(maxsize)
        self.out_queue = queue.Queue(maxsize)

    ##get packet from the queue interface
    # @param in_or_out - use 'in' or 'out' interface
    def get(self, in_or_out):
        try:
            if in_or_out == 'in':
                pkt_S = self.in_queue.get(False)
                # if pkt_S is not None:
                #     print('getting packet from the IN queue')
                return pkt_S
            else:
                pkt_S = self.out_queue.get(False)
                # if pkt_S is not None:
                #     print('getting packet from the OUT queue')
                return pkt_S
        except queue.Empty:
            return None

    ##put the packet into the interface queue
    # @param pkt - Packet to be inserted into the queue
    # @param in_or_out - use 'in' or 'out' interface
    # @param block - if True, block until room in queue, if False may throw queue.Full exception
    def put(self, pkt, in_or_out, block=False):
        if in_or_out == 'out':
            # print('putting packet in the OUT queue')
            self.out_queue.put(pkt, block)
        else:
            # print('putting packet in the IN queue')
            self.in_queue.put(pkt, block)


## Implements a network layer packet.
class NetworkPacket:
    ## packet encoding lengths
    dst_S_length = 5
    prot_S_length = 1

    ##@param dst: address of the destination host
    # @param data_S: packet payload
    # @param prot_S: upper layer protocol for the packet (data, or control)
    def __init__(self, dst, prot_S, data_S):
        self.dst = dst
        self.data_S = data_S
        self.prot_S = prot_S

    ## called when printing the object
    def __str__(self):
        return self.to_byte_S()

    ## convert packet to a byte string for transmission over links
    def to_byte_S(self):
        byte_S = str(self.dst).zfill(self.dst_S_length)
        if self.prot_S == 'data':
            byte_S += '1'
        elif self.prot_S == 'control':
            byte_S += '2'
        else:
            raise ('%s: unknown prot_S option: %s' % (self, self.prot_S))
        byte_S += self.data_S
        return byte_S

    ## extract a packet object from a byte string
    # @param byte_S: byte string representation of the packet
    @classmethod
    def from_byte_S(self, byte_S):
        dst = byte_S[0: NetworkPacket.dst_S_length].strip('0')
        prot_S = byte_S[NetworkPacket.dst_S_length: NetworkPacket.dst_S_length + NetworkPacket.prot_S_length]
        if prot_S == '1':
            prot_S = 'data'
        elif prot_S == '2':
            prot_S = 'control'
        else:
            raise ('%s: unknown prot_S field: %s' % (self, prot_S))
        data_S = byte_S[NetworkPacket.dst_S_length + NetworkPacket.prot_S_length:]
        return self(dst, prot_S, data_S)


## Implements a network host for receiving and transmitting data
class Host:

    ##@param addr: address of this node represented as an integer
    def __init__(self, addr):
        self.addr = addr
        self.intf_L = [Interface()]
        self.stop = False  # for thread termination

    ## called when printing the object
    def __str__(self):
        return self.addr

    ## create a packet and enqueue for transmission
    # @param dst: destination address for the packet
    # @param data_S: data being transmitted to the network layer
    def udt_send(self, dst, data_S):
        p = NetworkPacket(dst, 'data', data_S)
        print('%s: sending packet "%s"' % (self, p))
        self.intf_L[0].put(p.to_byte_S(), 'out')  # send packets always enqueued successfully

    ## receive packet from the network layer
    def udt_receive(self):
        pkt_S = self.intf_L[0].get('in')
        if pkt_S is not None:
            print('%s: received packet "%s"' % (self, pkt_S))
            print()

    ## thread target for the host to keep receiving data
    def run(self):
        print(threading.currentThread().getName() + ': Starting')
        while True:
            # receive data arriving to the in interface
            self.udt_receive()
            # terminate
            if (self.stop):
                print(threading.currentThread().getName() + ': Ending')
                return


## Implements a multi-interface router
class Router:

    ##@param name: friendly router name for debugging
    # @param cost_D: cost table to neighbors {neighbor: {interface: cost}}
    # @param max_queue_size: max queue length (passed to Interface)
    def __init__(self, name, cost_D, max_queue_size):
        self.stop = False  # for thread termination
        self.name = name
        # create a list of interfaces
        self.intf_L = [Interface(max_queue_size) for _ in range(len(cost_D))]
        # save neighbors and interfaces on which we connect to them
        self.cost_D = cost_D  # {neighbor: {interface: cost}}

        self.rt_tbl_D = {}  # {destination: {router: cost}}
        for key, value in cost_D.items():
            for innerKey, innerValue in cost_D[key].items():
                self.rt_tbl_D.update({key: {self.name: innerValue}})

        print('%s: Initialized routing table' % self)
        # self.print_routes()

    ## Print routing table
    def print_routes(self):

        print('%s: routing table' % self)
        # TODO: print the routes as a two dimensional table for easy inspection
        # Currently the function just prints the route table as a dictionary
        columns = list()
        for key, value in self.rt_tbl_D.items():
            columns.insert(len(columns), key)
        print("|======", end="")
        for i in range(len(columns)):
            print("|======", end="")
        print("|")
        dest = "| " + self.name + "   |"
        for i in columns:
            dest += " " + (str(i)) + "   |"
        print(dest)
        print("|======", end="")
        for i in range(len(columns)):
            print("|======", end="")
        print("|")
        src = ""
        row_keys = set()
        for i in set(self.rt_tbl_D.keys()):
            row_keys.update(self.rt_tbl_D[i].keys())
        for i in row_keys:
            src += "| " + str(i) + "   |"
            for j in columns:
                key1 = self.rt_tbl_D.get(j)
                if key1 is not None and i in key1.keys():
                    key2 = key1.get(i)
                    if key2 is not None:
                        src += " " + str(key2) + "    |"
                    else:
                        src += " ~    |"
                else:
                    src += " ~    |"
            print(src)
            src = ""
        print("|======", end="")
        for i in range(len(columns)):
            print("|======", end="")
        print("|")
        print(self.rt_tbl_D)
        print()

    ## called when printing the object
    def __str__(self):
        return self.name

    ## look through the content of incoming interfaces and
    # process data and control packets
    def process_queues(self):
        for i in range(len(self.intf_L)):
            pkt_S = None
            # get packet from interface i
            pkt_S = self.intf_L[i].get('in')
            # if packet exists make a forwarding decision
            if pkt_S is not None:
                p = NetworkPacket.from_byte_S(pkt_S)  # parse a packet out
                if p.prot_S == 'data':
                    self.forward_packet(p, i)
                elif p.prot_S == 'control':
                    self.update_routes(p, i)
                else:
                    raise Exception('%s: Unknown packet type in packet %s' % (self, p))

    ## forward the packet according to the routing table
    #  @param p Packet to forward
    #  @param i Incoming interface number for packet p
    def forward_packet(self, p, i):
        try:
            # TODO: Here you will need to implement a lookup into the
            # forwarding table to find the appropriate outgoing interface
            #Need where we are, and where we are going. Then check our routing table, and look for our interface first.
            #To do this, we will need to know where we're going

            #OR, we could just try sending it along the interface if there's an option for that interface. If not, lookup
            outInterface = self.cost_D.values()
            intfCount = 0
            outCount = 0
            out = ''

            for entry in self.cost_D:
                #Gives the interface of each of our neighbors
                for key in self.cost_D[entry]:
                    print("Entry",key)
                    if key == i:
                        intfCount += 1
                    outCount += 1
               # print("entry ",self.cost_D[entry].keys())

            print("Forward Packet, out, packet: ",out,p)


            packet = p.to_byte_S()
            dest = packet[3:4]
            nodeTarget = dest
            # Do a 1 node search to see if the target is close, and move that way if it is
            if dest in self.cost_D.keys():
                out = int(str(self.cost_D[dest])[1])
            #If we've only got one option with our interface
            elif intfCount == 1:
                out = i
                #print("coco")

            #Then, if multiple options of our interface, or other interfaces, do the lookup
            else:
                low = 99
                #If we have our interfaces to choose from
                if intfCount > 1:

                    for key in self.cost_D:
                        #So long as it shares our interface
                        #print("custard",int(str(self.cost_D[key])[4]))
                        if int(str(self.cost_D[key])[1]) == i:
                            if int(str(self.cost_D[key])[4]) < low:
                                out = int(str(self.cost_D[key])[1])

                #If the only options are other interfaces
                else:
                    #print("cookie")
                    for key in self.cost_D:
                        if int(str(self.cost_D[key])[4]) < low:
                            out = int(str(self.cost_D[key])[1])

           # print("Waffle i and out:",i,"     ",out)

            print('%s: forwarding packet "%s" from interface %d to %d' % (self, p, i, out))

            self.intf_L[out].put(p.to_byte_S(), 'out', True)

        except queue.Full:
            print('%s: packet "%s" lost on interface %d' % (self, p, i))
            pass

    ## send out route update
    # @param i Interface number on which to send out a routing update
    def send_routes(self, i):
        # TODO: See if this works

        route = str(self.rt_tbl_D)
        # for item in self.rt_tbl_D:
        #     print("Item:", item)
        # print("route: " + route)

        # create a routing table update packet
        p = NetworkPacket(0, 'control', route)
        try:
            print()
            print('%s: sending routing update "%s" from interface %d' % (self, p, i))
            self.intf_L[i].put(p.to_byte_S(), 'out', True)
        except queue.Full:
            print('%s: packet "%s" lost on interface %d' % (self, p, i))
            pass

    ## forward the packet according to the routing table
    #  @param p Packet containing routing information

    def update_routes(self, p, i):
        # TODO: add logic to update the routing tables, and add interface functionality
        INF = 99
        changed = False

        print()
        #print('%s: Received routing update %s from interface %d' % (self, p, i))
        # possibly send out routing updates
        dataIn = p.data_S
        #print("CONTROL DATA in router", self.name)
        #print("dataIn before split", dataIn[2])
        dataIn = re.sub('\{|\}|\'|(\s+)', '', dataIn)
        dataIn = re.split(',', dataIn)
        #print("D_Cost is:", self.cost_D)
        print("Our self table i:,", self.rt_tbl_D)

        rtable = self.rt_tbl_D
        # Dictionary of our neighbors (their name as key)
        neighbors = self.cost_D

        print("my rtable is", rtable)

        # Initializing Bellman-ford (mostly from book):
        # Set all of our known nodes to inf
        # Set up OUR neighbors distances (which we know)
        # Send our table to our neighbors

        # Set everything to inf

        # Reform the dictionary from the received string so it's workable
        for item in dataIn:
            # makes item a usable list item[0] is first, each 2 after that are the costs
            item = re.split('\:', item)
            # print("Item:", item)
            # for thing in item:
            # print("thing: " +thing)

            ##Set all non-neighbor costs to inf, neighbors includes this node
            # if item[0] not in neighbors:
            #   rtable[item[0]] = {item[1]: INF}

            if item[0] not in rtable:
                rtable[item[0]] = {item[1]: int(item[2])}
                changed = True

            # Go through whatever we've received and update costs if they're smaller than what we have now
            elif item[0] in rtable:

                if len(item) > 2 and int(item[2]) < rtable[item[0]][item[1]]:
                    rtable[item[0]] = {item[1]: int(item[2])}
                    changed = True
                    pass

            # Set the cost to ourselves to 0, this part may be nullified if we fill in our neighbors above
            if item[0] == self.name:
                # Set our cost to ourselves as 0
                rtable[self.name][self.name] = 0
                #changed = True

            #print("rtable is", rtable)

            # if item[0] == self.name:
            # print("Item - with our name:", item)

        # If we end up making a change , we want to send out an update to everybody relevant
        # Bellman-ford algorithm:
        while True:
            # "(wait until I see a link cost change to some neighbor w or until I receive a distance vector from some neighbor w)"

            # Adding locations we don't have
            if item[0] not in rtable:
                rtable[item[0]] = {item[1]: int(item[2])}
                changed = True
            #
            # # Go through whatever we've received and update costs if they're smaller than what we have now
            elif item[0] in rtable:
                pass
            #
            # #Set the cost to ourselves to 0, this part may be nullified if we fill in our neighbors above
            if item[0] == self.name:
                #     # Set our cost to ourselves as 0
                rtable[self.name][self.name] = 0
                changed = True

            # If something was changed, then send out our routing table again
            if changed:
                # I think this will send it to our neighbors?
                self.send_routes(i)

            break

        # self.rt_tbl_D = rtable
        print()
        print("Updated table:")
        self.print_routes()

    ## thread target for the host to keep forwarding data
    def run(self):
        print(threading.currentThread().getName() + ': Starting')
        while True:
            self.process_queues()
            if self.stop:
                print(threading.currentThread().getName() + ': Ending')
                return 
