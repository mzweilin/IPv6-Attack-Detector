import threading, md5
from scapy.all import *
from common import *
import message
import struct, os
        
class Globalpot(threading.Thread):
    
    def __init__(self, cfg, msg_queue):
        threading.Thread.__init__(self)
        self.iface = cfg['iface']
        
        self.msg = message.Message(msg_queue)
        self.msg.user = 'Globalpot'
        self.msg.msg_templete['attacker'] = 'Unknown'
        self.msg.msg_templete['victim'] = 'The whole network'
        
        # RAguard is responsible for detecting fake_router6, flood_router6, kill_router6
        self.ras = {}
        self.spoofing_ras = {} #{ra: counter}
        self.spoofing_counter = {} # {timestamp: counter}
        
        self.genuine_ra = ""
        self.genuine_router_addr = ""
        self.genuine_ra_hash = ""
        
        self.received_ra_flag = False
        self.flood_ra_flag = False
    
        # NSGuard is responsible for detecting , flood_solicitate6, rsmurf6, sendpeesmp6
        self.flood_ns_flag = False
        self.ns_counter = {} # {timestamp: counter}
        
        # NAGuard is responsible for detecting fake_advertise6, flood_advertise6
        self.flood_na_flag = False
        self.na_counter = {} # {timestamp: counter}
        
        # DHCPCGuard is responsible for detecting flood_dhcpc6
        self.flood_dhcpc_flag = False
        self.dhcpc_counter = {} # {timestamp: counter}
        
        
    def ra_init(self):
        filename = "globalpot_genuine_ra.pcap"
        location = './conf/' + filename
        if os.path.isfile(location):
            pcap_file = rdpcap(location)
            pkt = pcap_file[0]
            ra = pkt[ICMPv6ND_RA]
            ra.cksum = 0
            md5hash = md5.md5(str(ra)).hexdigest()
            
            self.genuine_ra_hash = md5hash
            self.genuine_ra = pkt
            iface_id = in6_mactoifaceid(self.genuine_ra.lladdr).lower()
            self.genuine_router_addr = in6_ptop("fe80::" + iface_id)
            print "Have selected the saved Router Advertisement as the genuine one."
            self.print_ra(self.genuine_ra)
            return True
        ra_lfilter = lambda (r): IPv6 in r and ICMPv6ND_RA in r
        # Send a Router Solicitation to get all Router Advertisement messages.
        # In the future, it can call IPv6 honeypots to send RS message.
        timeout = 5
        # Scapy BPF filtering is not working when some exotic interface are used. This includes Virtualbox interface such as vboxnet.
        # From https://home.regit.org/2012/06/using-scapy-lfilter/
        while not self.received_ra_flag:
            print "Please wait %d seconds to sniff Router Advertisement: " % timeout
            sniff(iface=self.iface, filter="icmp6", lfilter = ra_lfilter, prn=self.sniff_ra, timeout = timeout)
        self.select_genuine_ra()
        print "The genuine Router Advertisement is: "
        self.print_ra(self.genuine_ra)
    
    def run(self):
        globalpot_filter = "ip6 and (dst host ff02::1 or ff02::1:2)"
        globalpot_lfilter = lambda (r): IPv6 in r and (r[IPv6].dst == 'ff02::1' or r[IPv6].dst == 'ff02::1:2')
        self.ra_init()
        print "Globalpot starts.\n"
        sniff(iface=self.iface, filter=globalpot_filter, lfilter = globalpot_lfilter, prn=self.process)
    
    def process(self, pkt):
        #if self.pre_attack_detector(pkt) != 0:
        #    return
        if pkt[IPv6].dst == 'ff02::1':
            if ICMPv6ND_RA in pkt:
                self.ra_guard(pkt)
            elif ICMPv6ND_NS in pkt:
                self.ns_guard(pkt)
            elif ICMPv6ND_NA in pkt:
                self.na_guard(pkt)
            elif HBHOptUnknown in pkt or ICMPv6EchoRequest in pkt:
                self.host_discovery_guard(pkt)
        elif pkt[IPv6].dst == 'ff02::1:2' and DHCP6_Solicit in pkt:
            self.dhcpc_guard(pkt)

    # Handle the IPv6 invalid extention header options. (One of Nmap's host discovery technique.)
    
    def host_discovery_guard(self, pkt):
    
        # known_option_types = (0x0,0x1,0xc2,0xc3,0x4,0x5,0x26,0x7,0x8,0xc9,0x8a,0x1e,0x3e,0x5e,0x63,0x7e,0x9e,0xbe,0xde,0xfe)
        # Use the known list of Scapy's parser.
        # The allocated option types are listd in http://www.iana.org/assignments/ipv6-parameters/.
        # When receives a packet with unrecognizable options of destination extension header or hop-by-hop extension header, the IPv6 node should reply a Parameter Problem message.
        # RFC 2460, section 4.2 defines the TLV format of options headers, and the actions that will be take when received a unrecognizable option.
        # The action depends on the highest-order two bits:
        # 11 - discard the packet and, only if the packet's dst addr was not a multicast address, send ICMP Parameter Problem, Code 2, message to the src addr.
        # 10 - discard the packet and, regardless of whether or not the packet's dstaddr was a multicast address, send an parameter problem message.
        if HBHOptUnknown in pkt:
            if (pkt[HBHOptUnknown].otype & 0xc0) == 0xc0: 
                dst_type = in6_getAddrType(pkt[IPv6].dst)
                if (dst_type & IPV6_ADDR_MULTICAST) == IPv6_ADDR_MULTICAST:
                    return
            elif pkt[HBHOptUnknown].otype & 0x80 != 0x80:
                return
            msg = self.msg.new_msg(pkt)
            msg['type'] = 'HostDiscovery'
            msg['name'] = 'ICMPv6 invalid extension header'
            msg['attacker'] = pkt[IPv6].src
            msg['attacker_mac'] = pkt[Ether].src
            msg['util'] = 'Nmap, THC-IPv6-alive6'
            self.msg.put_attack(msg)
        elif ICMPv6EchoRequest in pkt:
            msg = self.msg.new_msg(pkt)
            msg['type'] = "HostDiscovery"
            msg['name'] = "ICMPv6 Echo Ping"
            msg['attacker'] = pkt[IPv6].src
            msg['attacker_mac'] = pkt[Ether].src
            msg['util'] = "Ping, Nmap, THC-IPv6-alive6"
            self.msg.put_attack(msg)
    
    def clear_flood_ns(self):
        self.flood_ns_flag = False
    
    def ns_guard(self, pkt):
        # Responsible for detecting THC-IPv6: sendpeesmp6
        if ICMPv6NDOptSrcLLAddr in pkt:
            src_type = in6_getAddrType(pkt[IPv6].src)
            #IPV6_ADDR_LINKLOCAL
            #IPV6_ADDR_GLOBAL
            if (src_type & IPV6_ADDR_LINKLOCAL) == IPV6_ADDR_LINKLOCAL:
                # flood_solicitate6
                # Ignore the details of fake NSs while suffering flood NS attack.
                if self.flood_ns_flag == True:
                    return
                    
                timestamp = int(pkt.time)
                if not self.ns_counter.has_key(timestamp):
                    self.ns_counter[timestamp] = 1
                else:
                    self.ns_counter[timestamp] += 1
                
                if self.ns_counter[timestamp] > 5:
                    #print "Alert! Detected flood_solicitate6 attack!"
                    self.flood_ns_flag = True
                    msg = self.msg.new_msg(pkt, save_pcap = 0)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Flood Neighbor Solicitation to ff02::1'
                    msg['util'] = "THC-IPv6: flood_solicitate6"
                    self.msg.put_attack(msg)
                    
                    # Set a 5s timer to clear the flood ra alert.
                    clear_flood_ns = threading.Timer(5.0, self.clear_flood_ns)
                    clear_flood_ns.start()
                    return
            else:
                msg = self.msg.new_msg(pkt)
                msg['type'] = 'DoS'
                msg['name'] = 'Neighbor Solicitation to ff02::1'
                msg['attacker'] = pkt[IPv6].src
                msg['attacker_mac'] = pkt[Ether].src
                msg['victim'] = pkt[ICMPv6ND_NS].tgt
                msg['util'] = "THC-IPv6: rsmurf6 | sendpeesmp6"
                self.msg.put_attack(msg)
            return 1
        return 0
        
    def clear_flood_na(self):
        self.flood_na_flag = False
    
    def na_guard(self, pkt):
        if ICMPv6NDOptDstLLAddr in pkt:
            src_type = in6_getAddrType(pkt[IPv6].src)
            #IPV6_ADDR_LINKLOCAL
            #IPV6_ADDR_GLOBAL
            if (src_type & IPV6_ADDR_LINKLOCAL) == IPV6_ADDR_LINKLOCAL:
                # flood_advertise6
                # Ignore the details of fake NAs while suffering flood NA attack.
                if self.flood_na_flag == True:
                    return
                    
                timestamp = int(pkt.time)
                if not self.na_counter.has_key(timestamp):
                    self.na_counter[timestamp] = 1
                    msg = self.msg.new_msg(pkt)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Fake Neighbor Advertisement to ff02::1'
                    msg['tgt'] = pkt.tgt
                    msg['src'] = pkt[IPv6].src
                    msg['lladdr'] = pkt.lladdr
                    msg['util'] = "THC-IPv6: fake_advertise6"
                    self.msg.put_attack(msg)
                else:
                    # Detect the 2nd fake_advertise6 in a second, which is likely to be flood_advertise6.
                    self.na_counter[timestamp] += 1
                
                if self.na_counter[timestamp] > 5:
                    #print "Alert! Detected flood_advertise6 attack!"
                    self.flood_na_flag = True
                    msg = self.msg.new_msg(pkt, save_pcap = 0)
                    msg['type'] = 'DoS'
                    msg['name'] = 'Flood Neighbor Advertisement to ff02::1'
                    msg['util'] = "THC-IPv6: flood_advertise6"
                    self.msg.put_attack(msg)
                    
                    # Set a 5s timer to clear the flood ra alert.
                    clear_flood_na = threading.Timer(5.0, self.clear_flood_na)
                    clear_flood_na.start()
                    return
            return 1
        return 0
        
    def clear_flood_dhcpc(self):
        self.flood_dhcpc_flag = False
    
    def dhcpc_guard(self, pkt):
        # flood_dhcpc6
        # Ignore the details of fake DHCPCs while suffering flood NA attack.
        if self.flood_dhcpc_flag == True:
            return
            
        timestamp = int(pkt.time)
        if not self.dhcpc_counter.has_key(timestamp):
            self.dhcpc_counter[timestamp] = 1
        else:
            self.dhcpc_counter[timestamp] += 1
        
        if self.dhcpc_counter[timestamp] > 5:
            #print "Alert! Detected flood_dhcpc6 attack!"
            self.flood_dhcpc_flag = True
            msg = self.msg.new_msg(pkt, save_pcap = 0)
            msg['type'] = 'DoS'
            msg['name'] = 'Flood DHCP Solicit'
            msg['util'] = "THC-IPv6: flood_dhcpc6"
            self.msg.put_attack(msg)
            
            # Set a 5s timer to clear the flood ra alert.
            clear_flood_dhcpc = threading.Timer(5.0, self.clear_flood_dhcpc)
            clear_flood_dhcpc.start()
            return
            return 1
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
            self.ras[md5hash] = [pkt, 1]
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
        self.genuine_router_addr = in6_ptop("fe80::" + iface_id)
        self.save_pcap(self.genuine_ra)
            
    def clear_flood_ra(self):
        self.flood_ra_flag = False
    
    # If the received RA doesn't match with the self.genuine_ra, print Alert!
    def ra_guard(self, pkt):
        if pkt[ICMPv6ND_RA].routerlifetime == 0 and pkt.haslayer(ICMPv6NDOptPrefixInfo):
            # SLAAC for host discovery.
            msg = self.msg.new_msg(pkt)
            msg['type'] = "HostDiscovery"
            msg['name'] = "ICMPv6 SLAAC-based"
            msg['attacker'] = pkt[IPv6].src
            if ICMPv6NDOptSrcLLAddr in pkt:
                msg['attacker_mac'] = pkt[ICMPv6NDOptSrcLLAddr].lladdr
            msg['util'] = "Nmap"
            self.msg.put_attack(msg)
            return
    
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
            ra = pkt[ICMPv6ND_RA]
            ra.cksum = 0
            md5hash = md5.md5(str(ra)).hexdigest()
            if md5hash != self.genuine_ra_hash:
                # RA spoofing against the genuine router
                if not ra.haslayer(ICMPv6NDOptPrefixInfo) or ra.routerlifetime < 100:
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

    # The format of pcap file references to http://wiki.wireshark.org/Development/LibpcapFileFormat/#Libpcap_File_Format
    def __get_pcap_hdr(self):
        #32bits
        magic_number = 0xa1b2c3d4
        #16bits
        version_major = 0x2
        #16bits
        version_minor = 0x4
        #32bits
        thiszone = 0
        #32bits
        sigfigs = 0
        #32bits
        snaplen = 0xffff
        #32bits, Ethernet
        network = 0x1
        return struct.pack('IHHIIII', magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network)
    
    def __get_pcaprec_hdr(self, pkt):
        time_str = "%f" % pkt.time
        
        # 32 + 32 bits, timestamp
        ts_sec, ts_usec = map(int, time_str.split('.'))
        #32bits
        incl_len = len(pkt)
        #32bits
        orig_len = len(pkt)
        return struct.pack('IIII', ts_sec, ts_usec, incl_len, orig_len)
        
    def save_pcap(self, pkt):
        #filename = "%s_%s.pcap" % (self.user, hash_str)
        filename = "globalpot_genuine_ra.pcap"
        location = './conf/' + filename
        pcap_file = open(location, 'wb')
        hdr = self.__get_pcap_hdr() + self.__get_pcaprec_hdr(pkt)
        pcap_file.write(hdr)
        pcap_file.write(str(pkt))
        pcap_file.close()
        return filename
