from scapy.all import *
import re

# Initiate the OUI list.
# OUI is short for 'Organizationally Unique Identifier'. We can learn the vendor of a network adapter from its MAC by the OUI list.
# The vendors' data is from http://standards.ieee.org/develop/regauth/oui/oui.txt on 2012/6/29, and it has been simplified for the release of IPv6 attack detector.
simple_oui = open('./simple_oui.txt', 'r')
oui_dict = {}
line = simple_oui.readline()
while line != '':
    paring = line.split('\t', 1)
    paring[1] = paring[1][:-1] # Delete the '\n'
    oui_dict[paring[0]] = paring[1]
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
    
def test():
    mac = "88:53:2E:C0:20:42"
    print mac2vendor(mac)
    
if __name__ == "__main__":
    test()
