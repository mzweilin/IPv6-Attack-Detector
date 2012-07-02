#!/usr/bin/env python
import binascii 
import socket
from scapy.all import *
import ConfigParser
from common import config
from common import logger
from common.common import *

# The class Honeypot emultates an IPv6 host.
# TODO: Generate MAC address with specified vendor (or prefix).
class Honeypot:
    #all_nodes_addr = inet_pton(socket.AF_INET6, "ff02::1")
    mac = ""
    iface_id = ""
    
    link_local_addr = "::"
    solicited_node_addr = "::"
    all_nodes_addr = "ff02::1"
    unspecified_addr = "::"
    unicast_addrs = {} # Directory {prefix: addr}, for the convenience of removing.
    
    # The probable addresses that may be used by honeypot as source address of packets.
    # Types: unspecified(::), link-local, unicast_addrs
    src_addrs = []
    
    # The probable destination addresses of captured packets that may relate to honeypot.
    # Types: all-nodes, solicited-node, link-local, unicast_addrs
    dst_addrs = []
    
    # Packet sending counter, with packet signatures.
    sent_sigs = {}
    
    # NDP-related dada structure.
    #self.solicited_list.append((target, dad_flag, timestamp))
    # {target_ip6:(dad_flag, timestamp)
    solicited_targets = {}
    # {target_ip6:(mac)}
    ip6_neigh = {}
    
    def __init__(self, config, log):
        self.log = log
        self.mac = config['mac']
        self.config = config
        self.iface = config['iface']
        
        self.iface_id = in6_mactoifaceid(self.mac).lower()
        self.link_local_addr = "fe80::" + self.iface_id
        self.link_local_addr = in6_ptop(self.link_local_addr)
        
        #FF02:0:0:0:0:1:FFXX:XXXX
        self.solicited_node_addr = "ff02:0:0:0:0:1:ff" + self.mac.split(':')[3] + ":" + "".join(self.mac.split(':')[4:6])
        self.solicited_node_addr = in6_ptop(self.solicited_node_addr)
        print "self.solicited_node_addr: " + self.solicited_node_addr
        
        scapy_solicited_node_addr = inet_ntop6(in6_getnsma(inet_pton6(self.link_local_addr)))
        print "scapy_solicited_node_addr: " + scapy_solicited_node_addr
                
        # When sending packets, it will select one of these addresses as src_addr.
        self.src_addrs.append(self.link_local_addr)
        self.src_addrs.append(self.unspecified_addr)
        
        # Packets with these dst_addr will destinate to the honeypot.
        self.dst_addrs.append(self.link_local_addr)
        self.dst_addrs.append(self.solicited_node_addr)
        self.dst_addrs.append(self.all_nodes_addr)
        
    def start(self):
        log_msg = "===Initiated an IPv6 Low-interaction Honeypot.===\n"
        log_msg += "Interface: %s\n" % self.iface
        log_msg += "MAC: %s\n" % self.mac
        log_msg += "Link-local address: %s\n" % self.link_local_addr
        log_msg += "Unicast address: " + str(self.unicast_addrs.values())
        self.log.write(log_msg, 0)
        
        ip6_lfilter = lambda (r): IPv6 in r and TCP not in r and UDP not in r
        sniff(iface=self.iface, filter="ip6", lfilter=ip6_lfilter, prn=self.process)

    def process(self, pkt):
        # Check spoofing.
        if self.check_received(pkt) != 0:
            return
        if self.config['iv_ext_hdr'] == 1 and "IPv6ExtHdr" in pkt.summary():
            if self.do_invalid_exthdr(pkt) == 1:
                return
        if not verify_cksum(pkt):
            return
        if self.config['ndp'] == 1 and ([ICMPv6ND_NS] in pkt or ICMPv6ND_NA in pkt):
            self.do_NDP(pkt)
        elif (self.config['uecho'] == 1 or self.config['mecho'] == 1) and ICMPv6EchoRequest in pkt:
            self.do_ICMPv6Echo(pkt)
        elif self.config['slaac'] == 1 and ICMPv6ND_RA in pkt:
            self.do_slaac(pkt)
        return
    
    # Check up the recevied packets.
    # ret: 0: normal packets, need further processing.
    # ret: 1: sent by itself, just ignore the packets.
    # ret: 2: spoofing alert.
    def check_received(self, packet):
        sig = binascii.b2a_hex(str(packet))
        #print "received:"
        #print sig
        #print packet.summary()
        if self.sent_sigs.has_key(sig):
            #print "\nI sent it just now?"
            if self.sent_sigs[sig] >= 1:
                self.sent_sigs[sig] = self.sent_sigs[sig] -1
                return 1
            else:
                self.log.write("Duplicate spoofing Alert!")
                return 2
        else:
            if packet[Ether].src == self.mac :
                if packet[IPv6].src in self.src_addrs:
                    self.log.write("Spoofing Alert!")
                else:
                    self.log.write("Spoofing Alert! (with non-standard source address)")
                return 2
        return 0

    # Record the packet in self.sent_sigs{}, then send it to the pre-specified interface.
    def send_packet(self, packet):
        #sig = str(packet)
        sig = binascii.b2a_hex(str(packet))
        #print sig
        #print "\nsigs updated!"
        if self.sent_sigs.has_key(sig):
            self.sent_sigs[sig] = self.sent_sigs[sig] + 1
            #print self.sent_sigs
        else:
            self.sent_sigs[sig] = 1
        sendp(packet, iface=self.iface)
        self.log.write("Sent 1 packet: %s" % packet.summary(), 2)
        self.log.write("Packet hex: %s" % sig, 2)
        
    # Handle the IPv6 invalid extention header options. (One of Nmap's host discovery technique.)
    # ret: 0: Valid extension header, need further processing.
    # ret: 1: Invalid extension header, reply a parameter problem message.
    # The allocated option types are listd in http://www.iana.org/assignments/ipv6-parameters/.
    # When receives a packet with unrecognizable options of destination extension header or hop-by-hop extension header, the IPv6 node should reply a Parameter Problem message.
    # RFC 2460, section 4.2 defines the TLV format of options headers, and the actions that will be take when received a unrecognizable option.
    # The action depends on the highest-order two bits:
    # 11 - discard the packet and, only if the packet's dst addr was not a multicast address, send ICMP Parameter Problem, Code 2, message to the src addr.
    # 10 - discard the packet and, regardless of whether or not the packet's dstaddr was a multicast address, send an parameter problem message.
    def do_invalid_exthdr(self, pkt):
        # known_option_types = (0x0,0x1,0xc2,0xc3,0x4,0x5,0x26,0x7,0x8,0xc9,0x8a,0x1e,0x3e,0x5e,0x63,0x7e,0x9e,0xbe,0xde,0xfe)
        # Use the known list of Scapy's parser.
        if HBHOptUnknown not in pkt:
            return 0
        else:
            if (pkt[HBHOptUnknown].otype & 0xc0) == 0xc0: 
                dst_type = in6_getAddrType(pkt[IPv6].dst)
                if (dst_type & IPV6_ADDR_MULTICAST) == IPv6_ADDR_MULTICAST:
                    return 1
            elif pkt[HBHOptUnknown].otype & 0x80 != 0x80:
                return 1
            # send parameter problem message.
            unknown_opt_ptr = str(pkt[IPv6]).find(str(pkt[HBHOptUnknown]))
            reply = Ether(dst=pkt[Ether].src, src=self.mac)/IPv6(dst=pkt[IPv6].src, src=self.unicast_addrs.items()[0][1])/ICMPv6ParamProblem(code=2, ptr=unknown_opt_ptr)/pkt[IPv6]
            self.send_packet(reply)
            log_msg = "Host discovery by IPv6 invalid extention header.\n"
            log_msg += "From: [%s], MAC: %s (%s)." % (pkt[IPv6].src, pkt[Ether].src, mac2vendor(pkt[Ether].src))
            self.log.write(log_msg)
            return 1
    
    # Handle the received NDP packets.
    def do_NDP(self, pkt):
        if pkt.haslayer(ICMPv6ND_NA):
            if pkt[IPv6].dst in self.dst_addrs:
                print "ICMPv6ND_NA"
                log_msg = "Neighbour Advertisement received.\n"
                # Record the pair of IP6addr-to-MAC 
                # The multicast host discovery and SLAAC will elicit NS.
                target = pkt[ICMPv6ND_NA].tgt
                if target in self.solicited_targets.keys():
                    if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                        target_mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                        self.ip6_neigh[target] = target_mac
                        self.solicited_targets.pop(target)
                        log_msg += "[%s], MAC: %s (%s)." % (target, target_mac, mac2vendor(target_mac))
                else:
                    log_msg += "Alert: suspicious NA packet!"
                    
                self.log.write()
            return
        # Unexpected Neighbour Solicitation
        # 1. Duplicate Address Detection
        # 2. Request for MAC address
        log_msg = "Neighbour Solicitation received.\n"
        if pkt.haslayer(NDOptSrcLLAddr):
            src_mac = pkt[NDOptSrcLLAddr].lladdr
            log_msg += "[%s], MAC: %s (%s).\n" % (pkt[IPv6].src, src_mac, mac2vendor(src_mac))
        
        if not (pkt[ICMPv6ND_NS].tgt in self.unicast_addrs.values()):
            log_msg += "Irrelevant NS target [%s].\n" % pkt[ICMPv6ND_NS].tgt
            self.log.write(log_msg)
            return
        
        if pkt[IPv6].src == "ff02::1" and not pkt.haslayer(NDOptSrcLLAddr):
            # DAD mechanism
            # Duplicate Address!
            # Honeypot occupies the existing MAC?
            # Shutdown this honeypot, and record it in case of DoS attack against Honeypots.
            print "Duplicate Address!"
        else:
            # Request for MAC address, or abnormal request that should elicit an alert.
            ns = pkt[IPv6]
            src_type = in6_getAddrType(ns.src)
            if (src_type & IPV6_ADDR_UNICAST) == IPV6_ADDR_UNICAST:
                # check(record) MAC address
                # #response a Neighbour Advertisement
                reply = Ether(src=self.mac, dst=pkt[Ether].src)/IPv6(dst=pkt[IPv6].src, src=pkt[ICMPv6ND_NS].tgt)/ICMPv6ND_NA(tgt=pkt[ICMPv6ND_NS].tgt)/ICMPv6NDOptSrcLLAddr(lladdr=self.mac)
                print "reply.summary"
                #print reply.summary
                self.send_packet(reply)
            else:
                # record the suspicious attack.
                print "record the suspicious attack."

    # Handle the received ICMPv6 Echo packets.
    def do_ICMPv6Echo(self, req):
        #print "do_ICMPv6Echo(), receved: "
        #print req.summary
        
        ether_dst = req[Ether].src
        ether_src = self.mac

        ip6_dst = req[IPv6].src
        if req[IPv6].dst != "ff02::1":
            ip6_src = req[IPv6].dst
        else:
            ip6_src = self.unicast_addrs.items()[0][1] # How to select a source IPv6 address? It's a problem.
        echo_id = req[ICMPv6EchoRequest].id
        echo_seq = req[ICMPv6EchoRequest].seq
        echo_data = req[ICMPv6EchoRequest].data
                
        reply = Ether(src=ether_src, dst=ether_dst)/IPv6(dst=ip6_dst, src=ip6_src)/ICMPv6EchoReply(id=echo_id, seq=echo_seq, data=echo_data)
        #print "Echo Reply summary:"
        #print reply.summary
        self.send_packet(reply) 
        
        log_msg = "ICMPv6 Echo received.\n"
        log_msg += "From [%s], MAC: %s(%s).\n" % (ip6_dst, ether_dst, mac2vendor(ether_dst))
        self.log.write(log_msg)
        return
        
    def do_slaac(self, ra):
        log_msg = "Router Advertisement received.\n"
        if ICMPv6NDOptPrefixInfo not in ra or ICMPv6NDOptSrcLLAddr not in ra:
            log_msg += "Warning: No Prefix or SrcLLAddr, ignored."
            self.log.write(log_msg)
            return
        
        prefix = ra[ICMPv6NDOptPrefixInfo].prefix
        prefix_len = ra[ICMPv6NDOptPrefixInfo].prefixlen
        ra_mac = ra[ICMPv6NDOptSrcLLAddr].lladdr
        done, new_addr = self.add_prefix(prefix, prefix_len, timeout = 3600)
        if done:
            ns_reply = Ether(src=self.mac, dst=ra_mac)/IPv6(src=self.unspecified_addr, dst=self.solicited_node_addr)/ICMPv6ND_NS(code=0, tgt=new_addr)
            self.send_packet(ns_reply)
            log_msg += "Append a new IPv6 address: %s/%d" % (new_addr, prefix_len)
        else:
            log_msg += "Warning: Prefix illegal, ignored."
        self.log.write(log_msg)
        return
    
    # Add a network prefix to the honeypot, and generate a new IPv6 unicast address.
    # TODO: Handle the router lifetime.
    def add_prefix(self, prefix, prefix_len, timeout):
        # Section 5.5.3 of RFC 4862: 
        # If the sum of the prefix length and interface identifier length
        # does not equal 128 bits, the Prefix Information option MUST be
        # ignored.
        if prefix_len != 64:
            log_msg = "Warning: Prefix length is not equal to 64.\n"
            log_msg += "Prefix: %s/%d" % (prefix, prefix_len)
            self.log.write(log_msg, 0)
            return False
        prefix_n = inet_pton6(prefix)
        iface_id_n = inet_pton6("::"+self.iface_id)
        mask_n = in6_cidr2mask(prefix_len)
        valid_prefix_n = in6_and(prefix_n, mask_n)
        new_addr_n = in6_or(valid_prefix_n, iface_id_n)
        new_addr = inet_ntop6(new_addr_n)
        
        self.unicast_addrs[prefix] = new_addr
        self.src_addrs.append(new_addr)
        self.dst_addrs.append(new_addr)
        
        log_msg = "Prefix: %s/%d\n" % (prefix, prefix_len)
        log_msg += "Generated a new addr: %s" % (new_addr)
        self.log.write(log_msg)
        return True, new_addr
        
    # Send Neighbour Solicitation packets.
    # TODO: How to select a source IPv6 address? It's a problem.
    def send_NDP_NS(self, target, dad_flag=False):
        self.solicited_list.append((target, dad_flag, timestamp))
        
        target_n = inet_pton6(target)
        nsma_n = in6_getnsma(target_n)
        ip6_dst = inet_ntop6(nsma_n)
        mac_dst = in6_getnsmac(target_n)
        
        #ip6_dst = "ff02::1:ff"+target[-7:]
        #mac_dst = "33:33:ff"+":"+target[-7:-5]+":"+target[-4,-2]+":"+target[-2:]
        
        if dad == True:
            ip6_src = "::"
        else:
            ip6_src = self.unicast_addrs.items()[0][1]
        
        solic = Ether(dst=mac_dst, src=self.mac)/IPv6(src=ip6_src, dst=ip6_dst)/ICMPv6ND_NS(tgt=target)/ICMPv6NDOptSrcLLAddr(lladdr=self.mac)
        self.send_packet(solic)
        return
    
    def dhcpv6(self, req):
        return
    
def main():
    log = logger.Log("test.log")
    log.set_print_level(0)
    
    conf_file = "./conf/honeypot.ini"
    cfg = ConfigParser.SafeConfigParser()
    cfg.read(conf_file)
    try:
        config.parse_config(cfg)
    except config.ParsingError, err:
        print str(err)
        sys.exit(1)
    
    log.write("Configuration file <%s> loaded." % conf_file)
    
    vm = Honeypot(config.config, log)
    vm.add_prefix(prefix="2012:dead:beaf:face::", prefix_len=64, timeout=3600)
    vm.start()

if __name__ == "__main__":
    main()
