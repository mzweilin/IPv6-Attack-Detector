import threading, md5
from scapy.all import *
from common import *
import message
        
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
        
        self.msg = message.Message(msg_queue)
        self.msg.user = 'Globalpot'
        self.msg.msg_templete['attacker'] = 'Unknown'
        self.msg.msg_templete['victim'] = 'The whole network'
        self.msg.msg_templete['from'] = 'Globalpot'
        
        # RA Guard.
        self.flood_ra_flag = False
    
    def ra_init(self):
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
        globalpot_lfilter = lambda (r): IPv6 in r and r[IPv6].dst == 'ff02::1'
        self.ra_init()
        print "\n Globalpot is running..."
        sniff(iface=self.iface, filter="ip6", lfilter = globalpot_lfilter, prn=self.process)
    
    def process(self, pkt):
        if self.pre_attack_detector(pkt) != 0:
            return
        if ICMPv6ND_RA in pkt:
            self.ra_guard(pkt)
    
    def pre_attack_detector(self, pkt):
        return 0
    
    # Sniff all RAs and write them in self.ras
    # The structure of self.ras is,  {md5(ra): [ra, times]}
    def sniff_ra(self,pkt):
        # Filter the malformed Router Advertisement.
        if not pkt.haslayer(ICMPv6NDOptSrcLLAddr):
            return
        elif pkt[Ether].src != pkt[ICMPv6NDOptSrcLLAddr].lladdr:
            return
        # Filter RAs to other hosts.
        # Filter RAs sent by kill_router6.
        if not pkt.haslayer(ICMPv6NDOptPrefixInfo):
            return
        
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
        return
    
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
            
    def clear_flood_ra(self):
        self.flood_ra_flag = False
    
    # If the received RA doesn't match with the self.genuine_ra, print Alert!
    def ra_guard(self, pkt):
        if pkt[IPv6].src != self.genuine_router_addr:
            # It must be fake!
            # Detect flood_ra attack.
            # Ignore the details of fake RAs while suffering flood RA attack.
            if self.flood_ra_flag == True:
                return
            timestamp = int(pkt.time)
            if not self.spoofing_counter.has_key(timestamp):
                self.spoofing_counter[timestamp] = 1
            else:
                self.spoofing_counter[timestamp] += 1
            
            if self.spoofing_counter[timestamp] > 5:
                #print "Alert! Detected flood_router6 attack!"
                self.flood_ra_flag = True
                msg = self.msg.new_msg(pkt, save_pcap = 0)
                msg['type'] = 'DoS'
                msg['name'] = 'Flood Router Advertisement'
                msg['util'] = "THC-IPv6: flood_router6"
                self.msg.put_attack(msg)
                
                # Set a 5s timer to clear the flood ra alert.
                clear_flood_ra = threading.Timer(5.0, self.clear_flood_ra)
                clear_flood_ra.start()
                return
            
            if not pkt.haslayer(ICMPv6NDOptPrefixInfo):
                #log_msg = "Warning! Detected invalid kill_router6 attack."
                msg = self.msg.new_msg(pkt)
                msg['type'] = 'DoS'
                msg['name'] = 'Fake Router Advertisement against the fake router'
                msg['attacker'] = pkt[IPv6].src
                msg['attacker_mac'] = pkt[Ether].src
                msg['util'] = "THC-IPv6: kill_router6"
                self.msg.put_attack(msg)
            else:
                # fake_route6 attack or flood_route6 attack as a new router
                #log_msg = "Alert! Detected fake_route6 attack as new router!"
                msg = self.msg.new_msg(pkt)
                msg['type'] = 'DoS'
                msg['name'] = 'Fake Router Advertisement'
                msg['attacker'] = pkt[IPv6].src
                msg['attacker_mac'] = pkt[Ether].src
                msg['util'] = "THC-IPv6: fake_router6"
                self.msg.put_attack(msg)
        else:
            #TODO: It looks as if the result is wrong. Check it next time.
            ra = pkt[ICMPv6ND_RA]
            ra.cksum = 0
            md5hash = md5.md5(str(ra)).hexdigest()
            if md5hash != self.genuine_ra_hash:
                # RA spoofing against the genuine router
                if not ra.haslayer(ICMPv6NDOptPrefixInfo):
                    # suspicious kill_route6 attack
                    msg = self.msg.new_msg(pkt)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Fake Router Advertisement against the genuine router'
                    msg['util'] = "THC-IPv6: kill_router6"
                    self.msg.put_attack(msg)
                else:
                    #log_msg = "Alert! Detected fake_router6 attack against the genuine router!"
                    msg = self.msg.new_msg(pkt)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Fake Router Advertisement against the genuine router'
                    msg['util'] = "THC-IPv6: fake_router6"
                    self.msg.put_attack(msg)
            else:
                return



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

