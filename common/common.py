from scapy.all import *
import re
import random

__all__ = ["mac2vendor", "verify_cksum", "inet_ntop6", "inet_pton6"]

# Initiate the OUI list.
# OUI is short for 'Organizationally Unique Identifier'. We can learn the vendor of a network adapter from its MAC by the OUI list.
# The vendors' data is from http://standards.ieee.org/develop/regauth/oui/oui.txt on 2012/6/29, and it has been simplified for the release of IPv6 attack detector.
#simple_oui = open('./common/simple_oui.txt', 'r')
simple_oui = open('./simple_oui.txt', 'r')
oui_dict = {} # MAC prefix ==> Vendor
oui_rdict = {} # vendor.lower() ==> (vendor.native(), MAC prefixES LIST)

line = simple_oui.readline()
while line != '':
    paring = line.split('\t', 1)
    paring[1] = paring[1][:-1] # Delete the '\n'
    oui_dict[paring[0]] = paring[1]
    if oui_rdict.has_key(paring[1]):
        oui_rdict[paring[1].lower()][1].append(paring[0])
    else:
        oui_rdict[paring[1].lower()] = (paring[1], [paring[0]])
    line = simple_oui.readline()
mac_pattern = r'^[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}$'
mac_reg = re.compile(mac_pattern)

def mac2vendor(mac):
    mac = mac.upper()
    match = mac_reg.match(mac)
    if match == None:
        return None
    prefix = ''.join(mac[:8].split(':'))
    if oui_dict.has_key(prefix):
        return oui_dict[prefix]
    else:
        return None

def vendor2mac(vendor):
    hex_str = "0123456789ABCDEF"
    # First char Upper, all upper, all lower
    vendor = vendor.lower()
    for key in oui_rdict.keys():
        if key.find(vendor) != -1:
            # get a mac prefix
            print oui_rdict[key][1]
            prefix = random.choice(oui_rdict[key][1])
            print prefix
            mac = ""
            for i in range(0, 6, 2):
                mac += prefix[i:i+2] + ":"
            for i in range(0, 3):
                mac += random.choice(hex_str) + random.choice(hex_str)
                if i != 2:
                    mac += ':'
            return mac
    return None

# interactive mode of vendor2mac()
def vendor2mac_ia(keyword):
    can_list = []
    for vendor in oui_rdict.keys():
        if vendor.find(keyword) != -1:
            can_list.append(vendor)
    if len(can_list) == 0:
        return None
    if len(can_list) == 1:
        return vendor2mac(keyword)
    print "\nWhat's your mean when specifying \"%s\"?" % keyword
    for i in range(0, len(can_list)):
        print "%d. %s" % (i, oui_rdict[can_list[i]][0])
    choice = -1
    while choice<0 or choice>len(can_list)-1:
        choice = int(raw_input("Please input the index number: "))
    return vendor2mac(can_list[choice])

# Verify the checksum of packets.
def verify_cksum(pkt):
    # Scapy uses 'cksum' or 'chksum' to index checksum value.
    try:
        origin_cksum = pkt.cksum
        del pkt.cksum
        pkt = Ether(str(pkt))
        correct_cksum = pkt.cksum
    except AttributeError:
        try:
            origin_cksum = pkt.chksum
            del pkt.chksum
            pkt = Ether(str(pkt))
            correct_cksum = pkt.chksum
        except AttributeError:
            # No checksum.
            return True
    if origin_cksum == correct_cksum:
        return True
    return False
    
def inet_pton6(addr):
    return inet_pton(socket.AF_INET6, addr)

def inet_ntop6(addr):
    return inet_ntop(socket.AF_INET6, addr)
    
def test():
    #mac = "88:53:2E:C0:20:42"
    #print mac2vendor(mac)
    mac = vendor2mac_ia('zte')
    print mac
    print mac2vendor(mac)
    
if __name__ == "__main__":
    test()
