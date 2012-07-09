#!/usr/bin/env python
import socket, time
from scapy.all import *
import md5
from common import common
import sys, getopt

class RAguard:
    ras = {}
    spoofing_ras = {} #{ra: counter}
    spoofing_counter = {} # {timestamp: counter}
    
    mac = '08:00:27:ff:b5:24'
    lladdr = ''
    
    genuine_ra = ""
    genuine_router_addr = ""
    genuine_ra_hash = ""
    
    received_ra_flag = False
    
    def __init__(self, iface):
        self.iface = iface
    
    def start(self):
        # Send a Router Solicitation to get all Router Advertisement messages.
        # In the future, it can call IPv6 honeypots to send RS message.
        iface_id = in6_mactoifaceid(self.mac).lower()
        self.lladdr = "fe80::" + iface_id
        rs = Ether(src=self.mac, dst='33:33:00:00:00:02')/IPv6(src=self.lladdr, dst='ff02::2')/ICMPv6ND_RS()
        timeout = 5
        # Scapy BPF filtering is not working when some exotic interface are used. This includes Virtualbox interface such as vboxnet.
        # From https://home.regit.org/2012/06/using-scapy-lfilter/
        ra_lfilter = lambda (r): IPv6 in r and ICMPv6ND_RA in r
        while not self.received_ra_flag:
            print "Please wait %d seconds to sniff Router Advertisement: " % timeout
            sendp(rs, iface=self.iface)
            sniff(iface=self.iface, filter="ip6", lfilter = ra_lfilter, prn=self.sniff_ra, timeout = timeout)
        self.select_genuine_ra()
        print "The genuine Router Advertisement is: "
        self.print_ra(self.genuine_ra)
        print "\n RA Guard is running..."
        sniff(iface=self.iface, filter="ip6", lfilter = ra_lfilter, prn=self.ra_guard)
    
    # Sniff all RAs and write them in self.ras
    # The structure of self.ras is,  {md5(ra): [ra, times]}
    def sniff_ra(self,pkt):
        # Filter the malformed Router Advertisement.
        if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
            if pkt[Ether].src != pkt.lladdr:
                return False
        # Filter RAs to other hosts.
        if not in6_isaddrllallnodes(pkt[IPv6].dst) and not pkt[IPv6].dst == self.lladdr:
            return False
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
                    log_msg = "Alert! Detected kill_router6 attack against the genuine router!"
                else:
                    log_msg = "Alert! Detected fake_router6 attack against the genuine router!"
            elif not ra.haslayer(ICMPv6NDOptPrefixInfo):
                log_msg = "Warning! Detected invalid kill_router6 attack."
            else:
                # fake_route6 attack or flood_route6 attack as a new router
                log_msg = "Alert! Detected fake_route6 attack as new router!"
            print log_msg
            timestamp = int(time.time())
            if not self.spoofing_counter.has_key(timestamp):
                self.spoofing_counter[timestamp] = 1
            else:
                self.spoofing_counter[timestamp] += 1
                
            #print self.spoofing_counter
            
            if self.spoofing_counter[timestamp] > 9:
                print "Alert! Detected flood_router6 attack!"
                
            if self.spoofing_ras.has_key(md5hash):
                self.spoofing_ras[md5hash][1] += 1
                (spoofing_ra, times) = self.spoofing_ras[md5hash]
                log_msg = "%d times received the duplicate RA Spoofing!  " % (times)
                if spoofing_ra.haslayer(ICMPv6NDOptPrefixInfo):
                    log_msg += "Prefix/Len: %s/%d" % (spoofing_ra.prefix, spoofing_ra.prefixlen)
                print log_msg
            else:
                print "New RA Spoofing!"
                self.spoofing_ras[md5hash] = [ra, 1]
                self.print_ra(pkt)

    # Print Router Advertisement message in a readable form.
    def print_ra(self, ra):
        print 'Stateful address conf.    : %d' % (ra.M)
        print 'Stateful other conf.      : %d' % (ra.O)
        print 'Router lifetime           : %d   \t(0x%.4x) seconds' % (ra.routerlifetime, ra.routerlifetime)
        print 'Reachable time            : %d   \t(0x%.8x) microseconds' % (ra.reachabletime, ra.reachabletime)
        print 'Retransmit time           : %d   \t(0x%.8x) microseconds' % (ra.retranstimer, ra.retranstimer)
        if ra.haslayer(ICMPv6NDOptSrcLLAddr):
            print ' Source link-layer address: %s\t (%s)' % (ra.lladdr, common.mac2vendor(ra.lladdr))
        if ra.haslayer(ICMPv6NDOptMTU):
            print ' MTU                      : %d bytes' % ra.mtu
        if ra.haslayer(ICMPv6NDOptPrefixInfo):
            print ' Prefix                   : %s/%d' % (ra.prefix, ra.prefixlen)
            print '  Valid time              : %d (0x%x) seconds' \
                    % (ra.validlifetime, ra.validlifetime)
            print '  Pref. time              : %d (0x%x) seconds' \
                    % (ra.preferredlifetime, ra.preferredlifetime)
        print ""

    
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hi:", ["help", "interface="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ('-i', "--interface"):
            iface = arg
    if 'iface' not in dir():
        usage()
        sys.exit()
    
    raguard = RAguard(iface)
    raguard.start()
    
def usage():
    print "sudo ./ipv6-ra-guard.py -i <interface>"

if __name__ == "__main__":
    main(sys.argv[1:])
