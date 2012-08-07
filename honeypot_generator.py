# Generate honeypot configuration files in the ./conf directory.

import os
from common.common import *

def main():
    quantity = ""
    while not quantity.isdigit() or quantity <= 0:
         quantity = raw_input("The Quantity of honeypots [e.g. 50]: ")
    quantity = int(quantity)
    vendor = raw_input("The vendor keyword [e.g. apple]: ")
    mac_list = vendor2mac_ia(vendor, quantity)
    iface = raw_input("The network card interface [e.g. eth0]: ")

    for num in range(0, quantity):
        honeypot_name = "Honeypot-%s-%s" % (vendor, mac_list[num][9:])
        conf = "[main]\n"
        conf += "name = %s\n" % honeypot_name
        conf += "interface = %s\n" % iface
        conf += "mac = %s\n" % mac_list[num]
        conf += "\n"
        conf += "[IPv6]\nndp = 1\nicmpv6_echo_unicast = 1\nicmpv6_echo_multicast = 1\nicmpv6_invalid_exheader = 1\nslaac = 1\ndhcpv6 = 0\n"
        hp_file = open("./conf/" + honeypot_name+".ini", 'w')
        hp_file.write(conf)
        hp_file.close()
        
    
if __name__ == "__main__":
    main()
