import threading, md5
from scapy.all import *
from common import *
        
class Globalpot(threading.Thread):
    # RAguard is responsible for detecting fake_router6, flood_router6, kill_router6
    ras = {}
    spoofing_ras = {} #{ra: counter}
    spoofing_counter = {} # {timestamp: counter}
    
    genuine_ra = ""
    genuine_router_addr = ""
    genuine_ra_hash = ""
    
    received_ra_flag = False
    
    def __init__(self, msg_queue):
        threading.Thread.__init__(self)
        self.iface = 'eth5'
        self.msg_queue = msg_queue
        
    def put_msg(self, msg):
        msg['from'] = self.name
        self.msg_queue.put(msg)
        #TODO: send an event to notify the HCenter.
        
    def put_event(self, msg):
        msg['level'] = 'EVENT'
        self.put_msg(msg)
     
    def put_attack(self, msg):
        msg['level'] = 'ATTACK'
        self.put_msg(msg)
    
    def network_init(self):
        ra_lfilter = lambda (r): IPv6 in r and ICMPv6ND_RA in r
        # Send a Router Solicitation to get all Router Advertisement messages.
        # In the future, it can call IPv6 honeypots to send RS message.
        timeout = 5
        # Scapy BPF filtering is not working when some exotic interface are used. This includes Virtualbox interface such as vboxnet.
        # From https://home.regit.org/2012/06/using-scapy-lfilter/
        while not self.received_ra_flag:
            print "Please wait %d seconds to sniff Router Advertisement: " % timeout
            sniff(iface=self.iface, filter="ip6", lfilter = ra_lfilter, prn=self.sniff_ra, timeout = timeout)
        self.select_genuine_ra()
        print "The genuine Router Advertisement is: "
        self.print_ra(self.genuine_ra)
    
    def run(self):
        ra_lfilter = lambda (r): IPv6 in r and ICMPv6ND_RA in r
        self.network_init()
        print "\n RA Guard is running..."
        sniff(iface=self.iface, filter="ip6", lfilter = ra_lfilter, prn=self.ra_guard)
    
    # Sniff all RAs and write them in self.ras
    # The structure of self.ras is,  {md5(ra): [ra, times]}
    def sniff_ra(self,pkt):
        # Filter the malformed Router Advertisement.
        if not pkt.haslayer(ICMPv6NDOptSrcLLAddr):
            return False
        elif pkt[Ether].src != pkt[ICMPv6NDOptSrcLLAddr].lladdr:
            return False
        # Filter RAs to other hosts.
        # Filter RAs sent by kill_router6.
        if not pkt.haslayer(ICMPv6NDOptPrefixInfo):
            return False
        
        ra = pkt[ICMPv6ND_RA]
        ra.cksum = 0
        
        md5hash = md5.md5(str(ra)).hexdigest()
        
        if self.ras.has_key(md5hash):
            self.ras[md5hash][1] += 1
            #print "+1"
        else:
            self.ras[md5hash] = [ra, 1]
            #print "new"
        self.received_ra_flag = True
        return True
    
    # Select a geniune RA from sniffing result.
    def select_genuine_ra(self):
        if len(self.ras) == 1:
            self.genuine_ra_hash = self.ras.keys()[0]
            self.genuine_ra = self.ras[self.genuine_ra_hash][0]
            print "Have selected the unique Router Advertisement as the genuine one."
        else:
            # print all the RAs, and ask a choice.
            ra_list = [] # List element: 
            for md5hash, (ra, times) in self.ras.items():
                ra_list.append((md5hash, ra, times))
 
            for index, ra in enumerate(ra_list):
                print "Index: [%d], Frequency: %d" % (index, ra[2])
                self.print_ra(ra[1])
                
            select_index = -1
            while select_index < 0 or select_index >= len(ra_list):
                select_index = int(raw_input("Please select the [index] of the genuine Router Advertisement:"))
            self.genuine_ra = ra_list[select_index][1]
            self.genuine_ra_hash = ra_list[select_index][0]
            iface_id = in6_mactoifaceid(self.genuine_ra.lladdr).lower()
            self.genuine_router_addr = "fe80::" + iface_id
            
    # If the received RA doesn't match with the self.genuine_ra, print Alert!
    def ra_guard(self, pkt):
        ra = pkt[ICMPv6ND_RA]
        ra.cksum = 0
        
        md5hash = md5.md5(str(ra)).hexdigest()
        
        if md5hash != self.genuine_ra_hash:
            if pkt[IPv6].src == self.genuine_router_addr:
                # RA spoofing against the genuine router
                if not ra.haslayer(ICMPv6NDOptPrefixInfo):
                    # suspicious kill_route6 attack
                    msg = self.new_msg(pkt)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Fake Router Advertisement against the genuine router'
                    msg['util'] = "THC-IPv6: kill_router6"
                    self.put_attack(msg)
                else:
                    #log_msg = "Alert! Detected fake_router6 attack against the genuine router!"
                    msg = self.new_msg(pkt)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Fake Router Advertisement against the genuine router'
                    msg['util'] = "THC-IPv6: fake_router6"
                    self.put_attack(msg)
            elif not ra.haslayer(ICMPv6NDOptPrefixInfo):
                #log_msg = "Warning! Detected invalid kill_router6 attack."
                msg = self.new_msg(pkt)
                msg['type'] = 'DoS'
                msg['name'] = 'Fake Router Advertisement against the fake router'
                msg['attacker'] = pkt[IPv6].src
                msg['attacker_mac'] = pkt[Ether].src
                msg['util'] = "THC-IPv6: kill_router6"
                self.put_attack(msg)
            else:
                # fake_route6 attack or flood_route6 attack as a new router
                #log_msg = "Alert! Detected fake_route6 attack as new router!"
                msg = self.new_msg(pkt)
                msg['type'] = 'DoS'
                msg['name'] = 'Fake Router Advertisement'
                msg['attacker'] = pkt[IPv6].src
                msg['attacker_mac'] = pkt[Ether].src
                msg['util'] = "THC-IPv6: fake_router6"
                self.put_attack(msg)
            #print log_msg
            timestamp = int(time.time())
            if not self.spoofing_counter.has_key(timestamp):
                self.spoofing_counter[timestamp] = 1
            else:
                self.spoofing_counter[timestamp] += 1
                
            #print self.spoofing_counter
            
            if self.spoofing_counter[timestamp] > 9:
                #print "Alert! Detected flood_router6 attack!"
                msg = self.new_msg(pkt)
                msg['type'] = 'DoS'
                msg['name'] = 'Flood Router Advertisement'
                msg['util'] = "THC-IPv6: flood_router6"
                self.put_attack(msg)
                
            if self.spoofing_ras.has_key(md5hash):
                self.spoofing_ras[md5hash][1] += 1
                (spoofing_ra, times) = self.spoofing_ras[md5hash]
                log_msg = "%d times received the duplicate RA Spoofing!  " % (times)
                if spoofing_ra.haslayer(ICMPv6NDOptPrefixInfo):
                    log_msg += "Prefix/Len: %s/%d" % (spoofing_ra.prefix, spoofing_ra.prefixlen)
                #print log_msg
            else:
                #print "New RA Spoofing!"
                self.spoofing_ras[md5hash] = [ra, 1]
                #self.print_ra(pkt)

    # Print Router Advertisement message in a readable form.
    def print_ra(self, ra):
        print 'Stateful address conf.    : %d' % (ra.M)
        print 'Stateful other conf.      : %d' % (ra.O)
        print 'Router lifetime           : %d   \t(0x%.4x) seconds' % (ra.routerlifetime, ra.routerlifetime)
        print 'Reachable time            : %d   \t(0x%.8x) microseconds' % (ra.reachabletime, ra.reachabletime)
        print 'Retransmit time           : %d   \t(0x%.8x) microseconds' % (ra.retranstimer, ra.retranstimer)
        if ra.haslayer(ICMPv6NDOptSrcLLAddr):
            print ' Source link-layer address: %s\t (%s)' % (ra.lladdr, mac2vendor(ra.lladdr))
        if ra.haslayer(ICMPv6NDOptMTU):
            print ' MTU                      : %d bytes' % ra.mtu
        if ra.haslayer(ICMPv6NDOptPrefixInfo):
            # TODO: Print the address block information from Regional Internet Registry.
            print ' Prefix                   : %s/%d' % (ra.prefix, ra.prefixlen)
            print '  Valid time              : %d (0x%x) seconds' \
                    % (ra.validlifetime, ra.validlifetime)
            print '  Pref. time              : %d (0x%x) seconds' \
                    % (ra.preferredlifetime, ra.preferredlifetime)
        print ""
        
    # Build a new attack/event message entity.
    def new_msg(self, pkt):
        msg = {}
        msg['timestamp'] = pkt.time
        msg['attacker'] = 'Unknown'
        msg['victim'] = 'The whole network'
        msg['pcap'] = self.save_pcap(msg, pkt)
        return msg
        
    def save_pcap(self, msg, pkt):
        hash_str = md5.md5(str(pkt)).hexdigest()
        filename = "%s_%s.pcap" % ('Globalpot', hash_str)
        pcap_file = open("./pcap/"+filename, 'wb')
        pcap_file.write(str(pkt))
        pcap_file.close()
        return filename
