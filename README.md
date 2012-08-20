6Guard (IPv6 attack detector)
=============================

##Description
6Guard is an IPv6 attack detector aiming at link-local level security threats, including most attacks initiated by [the THC-IPv6 suit](http://thc.org/thc-ipv6/) and the advanced host discovery methods used by [Nmap](http://nmap.org). It can help the network administrators detect the link-local IPv6 attacks in the early stage.

6Guard is sponsered by Google Summer of Code 2012 and supported by The Honeynet Project organization. The project page is at [Project 9 - IPv6 attack detector (Xu)](https://www.honeynet.org/gsoc/slots).

Here is an example of the attacking alert message provided by 6Guard.

    [ATTACK]
    Timestamp: 2012-08-19 14:48:27
    Reported by: Honeypot-apple-2A:C4:2D
    Type: DoS
    Name: Fake Echo Request
    Attacker: [Unknown]  00:00:de:ad:be:ef (CETIA)
    Victim  : [Honeypot-apple-2A:C4:2D]  40:3C:FC:2A:C4:2D (Apple, Inc.)
    Utility: THC-IPv6: smurf6
    Packets: b12fe3415c1d61c1da085cb8811974a2.pcap


##Installation
1. Download and install [Scapy](http://www.secdev.org/projects/scapy/) in your machine. (Or `apt-get install python-scapy`)
2. Download the latest code from [Github/mzweilin/ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector) and extract it into a directory.


##Usage
1. Enter the directory of 6Guard.
2. Run `$ sudo ./conf_generator.py` to generate the configuration files.
3. Run `$ sudo ./6guadrd.py`.


**Note**
* If it is the first time running 6guard, it will remind you to choice a genuine Router Advertisement message.
* The attacking alert message will be printed in the screen in real time.
* The attacking alert message will be also stored in the log file './log/attack.log'.'
* The attacking alert message includes an item 'Packets', telling which pcap file in './pcap/' is the related one that can be reviewd in Wireshark.
