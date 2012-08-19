#!/usr/bin/env python
# Generate honeypot/globalpot configuration files in the ./conf directory.

import os, sys
from common.common import *

def main():
    print "\nWelcome to 6Guard configuration generator.\n"
    menu = """
            Configuration menu
    ----------------------------------
        1: Generate configurations
        2: Remove configurations
        q: Quit
    ----------------------------------
    """
    
    while True:
        print menu
        choice = raw_input("Input your choice: ")
        if choice == 'q':
            sys.exit()
        elif choice == '1':
            honeypot_cfg()
        elif choice == '2':
            os.system('rm ./conf/*.ini ./conf/*.pcap')
    
def honeypot_cfg():
    quantity = ""
    while not quantity.isdigit() or quantity <= 0:
         quantity = raw_input("The Quantity of honeypots [e.g. 50]: ")
    quantity = int(quantity)
    vendor = raw_input("The vendor keyword [e.g. apple]: ")
    mac_list = vendor2mac_ia(vendor, quantity)
    iface = raw_input("The network card interface [e.g. eth0]: ")
    
    globalpot_cfg(iface)

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
        
def globalpot_cfg(iface):
    conf = "[main]\n"
    conf += "name = Globalpot\n"
    conf += "interface = %s\n" % iface
    gp_file = open("./conf/globalpot.ini", 'w')
    gp_file.write(conf)
    gp_file.close()
    
if __name__ == "__main__":
    main()
