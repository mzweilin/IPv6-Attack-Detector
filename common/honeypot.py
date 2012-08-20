#!/usr/bin/env python
import os
import md5
import binascii 
import socket
import threading
from scapy.all import *
#import ConfigParser
#from common import config
import logger
from common import *
import message

# The class Honeypot emultates an IPv6 host.
# TODO: Generate MAC address with specified vendor (or prefix).
class Honeypot(threading.Thread):

    # Initiating variables.
    def __init_variable(self):
        # TODO: Stop the honeypot at any time. (By disabling all the configurable options.)
        # Stop flag
        self.stop = False

        #all_nodes_addr = inet_pton(socket.AF_INET6, "ff02::1")
        self.mac = ""
        self.iface_id = ""
        
        self.link_local_addr = "::"
        self.solicited_node_addr = "::"
        self.all_nodes_addr = "ff02::1"
        self.unspecified_addr = "::"
        self.unicast_addrs = {} # Directory {addr: [timestamp, valid_liftime, preferred_lifetime]}
        self.tentative_addrs = {} # Directory {addr: [timestamp, valid_liftime, preferred_lifetime]}
        self.addr_timer = {} # Directory {addr: threading.Timer()}
        self.dad_timer = {} # {addr: Threading_timer}
        
        # The probable addresses that may be used by honeypot as source address of packets.
        # Types: unspecified(::), link-local, unicast_addrs
        self.src_addrs = []
        
        # The probable destination addresses of captured packets that may relate to honeypot.
        # Types: all-nodes, solicited-node, link-local, unicast_addrs
        self.dst_addrs = []
        
        # Packet sending counter, with packet signatures.
        self.sent_sigs = {}
        
        # NDP-related dada structure.
        #self.solicited_list.append((target, dad_flag, timestamp))
        # {target_ip6:(dad_flag, timestamp)
        self.solicited_targets = {}
        # {target_ip6:(mac)}
        self.ip6_neigh = {}
    
    def __init__(self, config, msg_queue):
        threading.Thread.__init__(self)
        conf.verb = 0
        
        self.__init_variable()
        
        self.name = config['name']
        self.mac = config['mac']
        self.iface = config['iface']
        self.config = config
        
        self.msg = message.Message(msg_queue)
        self.msg.user = self.name
        self.msg.msg_templete['attacker'] = 'Unknown'
        self.msg.msg_templete['victim'] = self.name
        self.msg.msg_templete['victim_mac'] = self.mac
        
        log_file = "./log/%s.log" % self.name
        self.log = logger.Log(log_file)
        self.log.set_print_level(3)
        
        self.iface_id = in6_mactoifaceid(self.mac).lower()
        self.link_local_addr = "fe80::" + self.iface_id
        self.link_local_addr = in6_ptop(self.link_local_addr)
        
        #FF02:0:0:0:0:1:FFXX:XXXX
        self.solicited_node_addr = inet_ntop6(in6_getnsma(inet_pton6(self.link_local_addr)))
                
        # When sending packets, it will select one of these addresses as src_addr.
        self.src_addrs.append(self.link_local_addr)
        self.src_addrs.append(self.unspecified_addr)
        
        # Packets with these dst_addr will destinate to the honeypot.
        self.dst_addrs.append(self.link_local_addr)
        self.dst_addrs.append(self.solicited_node_addr)
        self.dst_addrs.append(self.all_nodes_addr)
        
    def __del__(self):
        self.log.close()
    
    def run(self):
        log_msg = "Start."
        self.log.info(log_msg)
        
        rs = Ether(src=self.mac, dst='33:33:00:00:00:02')/IPv6(src=self.link_local_addr, dst='ff02::2')/ICMPv6ND_RS()
        self.send_packet(rs)
        
        ip6_filter = "ip6 and not tcp and not udp"
        ip6_lfilter = lambda (r): IPv6 in r and TCP not in r and UDP not in r and r[IPv6].dst in self.dst_addrs
        sniff(iface=self.iface, filter=ip6_filter, lfilter=ip6_lfilter, prn=self.process)

    def process(self, pkt):
        if self.pre_attack_detector(pkt) != 0:
            return
        # Check spoofing.
        if self.check_received(pkt) != 0:
            return
        if self.config['iv_ext_hdr'] == 1 and "IPv6ExtHdr" in pkt.summary():
            if self.do_invalid_exthdr(pkt) == 1:
                return
        if not verify_cksum(pkt):
            return
        if self.config['ndp'] == 1 and (ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt):
            self.do_NDP(pkt)
        elif (self.config['uecho'] == 1 or self.config['mecho'] == 1) and ICMPv6EchoRequest in pkt:
            self.do_ICMPv6Echo(pkt)
        elif self.config['slaac'] == 1 and ICMPv6ND_RA in pkt:
            self.do_slaac(pkt)
        else:
            self.handle_attack(pkt)
        return
    
    # Check the attacking traffic before honeypot really handling it.
    def pre_attack_detector(self, pkt):
        # THC-IPv6: sendpees6
        if pkt.haslayer(ICMPv6ND_NS) and pkt.haslayer(ICMPv6NDOptSrcLLAddr) and pkt.haslayer(Raw) and len(pkt[Raw]) > 150:
            msg = self.msg.new_msg(pkt)
            msg['type'] = "DoS"
            msg['name'] = "Flood SEND NS"
            msg['util'] = "THC-IPv6: sendpees6"
            self.msg.put_attack(msg)
            print "attack"
            return 1
        return 0
    
    # Check up the recevied packets.
    # ret: 0: normal packets, need further processing.
    # ret: 1: sent by itself, just ignore the packets.
    # ret: 2: spoofing alert.
    # ret: 3: irrelevant packts.
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
            #else:
                #self.log.info("Duplicate spoofing Alert!")
                #return 2
        if packet[Ether].src == self.mac or packet[IPv6].src != "::" and packet[IPv6].src in self.src_addrs:
            msg = self.msg.new_msg(packet)
            if ICMPv6EchoRequest in packet:
                msg['type'] = 'DoS'
                msg['name'] = 'Fake Echo Request'
                msg['util'] = "THC-IPv6: smurf6"
            else:
                # TODO: How to handle the two attack alerts (FakePacket and DAD:Address in use) aiming at the same packet?
                msg['type'] = 'DoS|MitM'
                msg['name'] = 'FakePacket'
                msg['util'] = 'Unknown'
            msg['attacker'] = 'Unknown'
            msg['attacker_mac'] = 'Unknown'
            if packet[Ether].src != self.mac and packet[IPv6].src in self.src_addrs:
                msg['attacker'] = 'Unknown'
                msg['attacker_mac'] = packet[Ether].src
            elif packet[Ether].src == self.mac and packet[IPv6].src not in self.src_addrs:
                msg['attacker'] = packet[IPv6].src
                msg['attacker_mac'] = 'Unknown'
            self.msg.put_attack(msg)
            
            return 2
        #elif packet[Ether].dst != self.mac or packet[IPv6].dst not in self.dst_addrs:
        #TODO: Check MAC address.
        elif packet[IPv6].dst not in self.dst_addrs:
            return 3
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
        self.log.debug("Sent 1 packet: %s" % packet.summary())
        # The packet summary infomation is just enough.
        #self.log.debug("Packet hex: %s" % sig)
        
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
            if len(self.unicast_addrs) == 0:
                return 1
            # send parameter problem message.
            unknown_opt_ptr = str(pkt[IPv6]).find(str(pkt[HBHOptUnknown]))
            reply = Ether(dst=pkt[Ether].src, src=self.mac)/IPv6(dst=pkt[IPv6].src, src=self.unicast_addrs.keys()[0])/ICMPv6ParamProblem(code=2, ptr=unknown_opt_ptr)/pkt[IPv6]
            self.send_packet(reply)
            return 1
    
    # Handle the received NDP packets.
    def do_NDP(self, pkt):
        if pkt[IPv6].dst not in self.dst_addrs:
            return
            
        if pkt.haslayer(ICMPv6ND_NA):
            log_msg = "Neighbour Advertisement received.\n"
            # Record the pair of IP6addr-to-MAC 
            # The multicast host discovery and SLAAC will elicit NS.
            target = pkt[ICMPv6ND_NA].tgt
            if self.solicited_targets.has_key(target):
                if pkt.haslayer(ICMPv6NDOptDstLLAddr):
                    target_mac = pkt[ICMPv6NDOptDstLLAddr].lladdr
                    self.ip6_neigh[target] = target_mac
                    log_msg += "[%s], MAC: %s (%s).\n" % (target, target_mac, mac2vendor(target_mac))
                    msg = self.msg.new_msg(pkt)
                    if self.solicited_targets[target][0] == True: # DAD
                        if self.tentative_addrs.has_key(target):
                            self.tentative_addrs.pop(target)
                        #log_msg += "DAD result: Address [%s] in use." % target
                        # Report this address-in-use event to 6guard, so as to detect the dos-new-ip6 attack.
                        msg['type'] = "DAD"
                        msg['name'] = "Address in use"
                        msg['attacker'] = "Unknown"
                        msg['attacker_mac'] = pkt[Ether].src
                        msg['victim'] = self.name
                        msg['victim_mac'] = self.mac
                        msg['util'] = "Unknown"
                        self.msg.put_event(msg)
                        if self.dad_timer.has_key(target):
                            self.dad_timer[target].cancel()
                            del self.dad_timer[target]
                    else:
                        # Report this Neighbour Advertisement event to 6guard, so as to detect the parasite6 attack.
                        msg['type'] = "NDP"
                        msg['name'] = "Neighbour Advertisement"
                        msg['attacker'] = pkt[IPv6].src
                        msg['attacker_mac'] = pkt[Ether].src
                        msg['target'] = pkt[ICMPv6ND_NA].tgt
                        msg['lladdr'] = pkt[ICMPv6NDOptDstLLAddr].lladdr
                        msg['util'] = "Unknown"
                        self.msg.put_event(msg)
                    self.solicited_targets.pop(target)
            else:
                if pkt[IPv6].dst != "ff02::1":
                    msg = self.msg.new_msg(pkt)
                    msg['type'] = "NDP"
                    msg['name'] = "Unsolicited Neighbor Advertisement"
                    msg['attacker'] = pkt[IPv6].src
                    msg['attacker_mac'] = pkt[Ether].src
                    msg['target'] = pkt[ICMPv6ND_NA].tgt
                    msg['lladdr'] = pkt[ICMPv6NDOptDstLLAddr].lladdr
                    msg['util'] = "THC-IPv6: fake_advertise6"
                    self.msg.put_attack(msg)
            
        # Unexpected Neighbour Solicitation
        # 1. Duplicate Address Detection
        # 2. Request for MAC address
        else:
            log_msg = "Neighbour Solicitation received.\n"
            if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                src_mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                log_msg += "[%s], MAC: %s (%s).\n" % (pkt[IPv6].src, src_mac, mac2vendor(src_mac))
                #TODO: I plan to ignore the message here, and collect the global IP-MAC paring in a central monitor program.
            
            if pkt[IPv6].src == "ff02::1" and not pkt.haslayer(NDOptSrcLLAddr):
                # DAD mechanism
                # Duplicate Address!
                # Honeypot occupies the existing MAC?
                # Shutdown this honeypot, and record it in case of DoS attack against Honeypots.
                log_msg += "[%s] has been used by MAC: %s" % (pkt[target], pkt[Ether].src)
                self.log.warning(log_msg)
                return
                #TODO: delete the address, and report it to the central system, in order to detect dos-new-ip6 attack.
            else:
                # Request for MAC address, or abnormal request that should elicit an alert.
                ns = pkt[IPv6]
                src_type = in6_getAddrType(ns.src)
                if (src_type & IPV6_ADDR_UNICAST) == IPV6_ADDR_UNICAST:
                    # check(record) MAC address
                    # response a Neighbour Advertisement
                    reply = Ether(src=self.mac, dst=pkt[Ether].src)/IPv6(dst=pkt[IPv6].src, src=pkt[ICMPv6ND_NS].tgt)/ICMPv6ND_NA(tgt=pkt[ICMPv6ND_NS].tgt)/ICMPv6NDOptDstLLAddr(lladdr=self.mac)
                    self.send_packet(reply)
        self.log.debug(log_msg)

    # Handle the received ICMPv6 Echo packets.
    def do_ICMPv6Echo(self, req):
        #print "do_ICMPv6Echo(), receved: "
        #print req.summary
        if req[IPv6].dst != "ff02::1":
            msg = self.msg.new_msg(req)
            msg['type'] = "HostDiscovery"
            msg['name'] = "ICMPv6 Echo Ping"
            msg['attacker'] = req[IPv6].src
            msg['attacker_mac'] = req[Ether].src
            msg['util'] = "Ping, Nmap, THC-IPv6-alive6"
            self.msg.put_attack(msg)
        
        # Don't reply an echo withourt unicast address. 
        if len(self.unicast_addrs.keys()) == 0:
            return
        
        ether_dst = req[Ether].src
        ether_src = self.mac

        ip6_dst = req[IPv6].src
        if req[IPv6].dst != "ff02::1":
            ip6_src = req[IPv6].dst
        else:
            ip6_src = self.unicast_addrs.keys()[0] # How to select a source IPv6 address? It's a problem.
        echo_id = req[ICMPv6EchoRequest].id
        echo_seq = req[ICMPv6EchoRequest].seq
        echo_data = req[ICMPv6EchoRequest].data
                
        reply = Ether(src=ether_src, dst=ether_dst)/IPv6(dst=ip6_dst, src=ip6_src)/ICMPv6EchoReply(id=echo_id, seq=echo_seq, data=echo_data)
        #print "Echo Reply summary:"
        #print reply.summary
        self.send_packet(reply)
        return
        
    def do_slaac(self, ra):
        log_msg = "Router Advertisement received.\n"
        if ICMPv6NDOptPrefixInfo not in ra or ICMPv6NDOptSrcLLAddr not in ra:
            log_msg += "No Prefix or SrcLLAddr, ignored."
            self.log.debug(log_msg)
            return
        prefix = ra[ICMPv6NDOptPrefixInfo].prefix
        prefix_len = ra[ICMPv6NDOptPrefixInfo].prefixlen
        valid_lifetime = ra[ICMPv6NDOptPrefixInfo].validlifetime
        preferred_lifetime = ra[ICMPv6NDOptPrefixInfo].preferredlifetime
        timestamp = int(time.time())
        #ra_mac = ra[ICMPv6NDOptSrcLLAddr].lladdr
        new_addr = self.prefix2addr(prefix, prefix_len)
        # TODO: Whether the address has been applied.
        if new_addr:
            if self.unicast_addrs.has_key(new_addr):
                time_list = [timestamp, valid_lifetime, preferred_lifetime]
                self.update_addr(new_addr, time_list)
            else:
                if self.tentative_addrs.has_key(new_addr):
                    # DAD on-going.
                    pass
                else:
                    self.tentative_addrs[new_addr] = [timestamp, valid_lifetime, preferred_lifetime]
                    self.send_NDP_NS(new_addr, dad_flag=True)
                    # Check if the address has been used by other nodes after 5 seconds.
                    dad_check = threading.Timer(5.0, self.do_DAD, args = [new_addr])
                    dad_check.start()
                    self.dad_timer[new_addr] = dad_check
        else:
            log_msg += "Prefix illegal, ignored."
            self.log.warning(log_msg)
        return
        
    def do_DAD(self, addr):
        if self.tentative_addrs.has_key(addr):
            time_list = self.tentative_addrs[addr]
            self.add_addr(addr, 64, time_list)
            self.tentative_addrs.pop(addr)
            if self.solicited_targets.has_key(addr):
                self.solicited_targets.pop(addr)
            log_msg = "DAD completed."
            self.log.debug(log_msg)
        # self.do_NDP() will handle the 'else'
    
    # Add a unicast address to the honeypot.
    def add_addr(self, new_addr, prefix_len, time_list):
        if self.unicast_addrs.has_key(new_addr):
            log_msg = "Address [%s] already exists on the interface." % new_addr
            self.log.info(log_msg)
            return
        self.unicast_addrs[new_addr] = time_list
        timestamp, valid_lifetime, preferred_lifetime = time_list
        if valid_lifetime != 0xffffffff: # non-infinity time.
            self.addr_timer[new_addr] = threading.Timer(valid_lifetime, self.del_addr, args = [new_addr])
            self.addr_timer[new_addr].start()
        self.src_addrs.append(new_addr)
        self.dst_addrs.append(new_addr)
        
        log_msg = "Add a new address: %s/%d" % (new_addr, prefix_len)
        self.log.info(log_msg)
        return
        
    def update_addr(self, addr, time_list):
        if not self.unicast_addrs.has_key(addr):
            return
        timestamp, valid_lifetime, preferred_lifetime = time_list
        self.unicast_addrs[addr] = time_list
        # It may be an infinity address before.
        if self.addr_timer.has_key(addr):
            self.addr_timer[addr].cancel()
            del self.addr_timer[addr]
        if valid_lifetime != 0xffffffff: # non-infinity time.
            self.addr_timer[addr] = threading.Timer(valid_lifetime, self.del_addr, args = [addr])
            self.addr_timer[addr].start()
        log_msg = "Updated the address [%s]." % addr
        self.log.info(log_msg)
        
    def del_addr(self, addr):
        if self.unicast_addrs.has_key(addr):
            del self.unicast_addrs[addr]
        if self.src_addrs.count(addr) != 0:
            self.src_addrs.remove(addr)
        if self.dst_addrs.count(addr) != 0:
            self.dst_addrs.remove(addr)
        if self.addr_timer.has_key(addr):
            self.addr_timer.pop(addr)
            log_msg = "Deleted an expired address: [%s]" % addr
        else:
            log_msg = "Deleted an address: [%s]" % addr
        self.log.info(log_msg)
    
    # Generate a new IPv6 unicast address like [Prefix + interface identifier]/Prefixlen.
    def prefix2addr(self, prefix, prefix_len):
        # Section 5.5.3 of RFC 4862: 
        # If the sum of the prefix length and interface identifier length
        # does not equal 128 bits, the Prefix Information option MUST be
        # ignored.
        if prefix_len != 64:
            log_msg = "Prefix length is not equal to 64.\n"
            log_msg += "Prefix: %s/%d" % (prefix, prefix_len)
            self.log.warning(log_msg)
            return None
        prefix_n = inet_pton6(prefix)
        iface_id_n = inet_pton6("::"+self.iface_id)
        mask_n = in6_cidr2mask(prefix_len)
        valid_prefix_n = in6_and(prefix_n, mask_n)
        new_addr_n = in6_or(valid_prefix_n, iface_id_n)
        new_addr = inet_ntop6(new_addr_n)
        return new_addr
    
    # Send Neighbour Solicitation packets.
    # TODO: How to select a source IPv6 address? It's a problem.
    def send_NDP_NS(self, target, dad_flag=False):
        self.solicited_targets[target] = (dad_flag, 0)
        
        target_n = inet_pton6(target)
        nsma_n = in6_getnsma(target_n)
        ip6_dst = inet_ntop6(nsma_n)
        mac_dst = in6_getnsmac(nsma_n)
        
        if dad_flag == True:
            ip6_src = "::"
            solic = Ether(dst=mac_dst, src=self.mac)/IPv6(src=ip6_src, dst=ip6_dst)/ICMPv6ND_NS(tgt=target)
            log_msg = "Duplicate Address Detection for [%s]." % target
        else:
            if len(self.unicast_addrs) == 0:
                ip6_src = self.link_local_addr
            else:
                ip6_src = self.unicast_addrs.keys()[0]
            solic = Ether(dst=mac_dst, src=self.mac)/IPv6(src=ip6_src, dst=ip6_dst)/ICMPv6ND_NS(tgt=target)/ICMPv6NDOptSrcLLAddr(lladdr=self.mac)
            log_msg = "Neighbour Solicitation for [%s]." % target 
        self.send_packet(solic)
        self.log.debug(log_msg)
        
        # Add a timer to delete the target in self.solicited_targets
        def del_solicited_target(target):
            if self.solicited_targets.has_key(target):
                del self.solicited_targets[target]
        if dad_flag == False:
            del_solicited_timer = threading.Timer(5.0, del_solicited_target, args=[target])
            del_solicited_timer.start()
        return
    
    def dhcpv6(self, req):
        return
        
    def handle_attack(self, pkt):
        # redir6 attack
        if ICMPv6ND_Redirect in pkt:
            msg = self.msg.new_msg(pkt)
            msg['type'] = 'MitM | DoS'
            msg['name'] = 'ICMPv6 Redirect'
            msg['attacker'] = pkt[ICMPv6ND_Redirect].tgt
            if ICMPv6NDOptDstLLAddr in pkt:
                msg['attacker_mac'] = pkt[ICMPv6NDOptDstLLAddr].lladdr
            msg['util'] = 'THC-IPv6-redir6'
            self.msg.put_attack(msg)
    
def main():
    # Disabled the Scapy output, such as 'Sent 1 packets.'.
    conf.verb = 0
    system_log = logger.Log("./log/system.log")
    system_log.set_print_level(1)
    
    # Loading the configuration files of honeypot. 
    confdir = './conf'
    cfg = ConfigParser.SafeConfigParser()
    honeypots = []
    for parent, dirnames, filenames in os.walk(confdir):
        for filename in filenames:
            split_name = filename.split('.')
            if len(split_name) == 2 and split_name[1] == 'ini':
                conf_file = os.path.join(parent, filename)
                cfg.read(conf_file)
                try:
                    config.parse_config(cfg)
                except config.ParsingError, err:
                    print str(err)
                    sys.exit(1)
                system_log.info("Configuration file <%s> loaded." % conf_file)
                
                honeypot_cfg = config.config.copy()
                config.config.clear()
                
                hp = Honeypot(honeypot_cfg)
                honeypots.append(hp)
                hp.setDaemon(True)
                static_ip6 = hp.prefix2addr(prefix="2013:dead:beef:face::", prefix_len=64)
                time_list = [0,1800,0]
                #hp.add_addr(static_ip6, 64, time_list)
                hp.start()
    
    try:
        raw_input("Honeypots are running...\n")
    except KeyboardInterrupt:
        for hp in honeypots:
            if hp.isAlive():
                hp.log.close()
        system_log.close()

if __name__ == "__main__":
    test()
