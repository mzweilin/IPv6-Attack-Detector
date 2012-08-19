import os
import md5
import struct

class Message():
    
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
    
    def __init__(self, msg_queue):
        self.msg_queue = msg_queue
        
        # Avoid putting flood msgs.
        # TODO: Clear the expired records.
        self.msg_record = {} # {timestamp: [str(msg)]}
        
        # The message instance can define its own message templete. Such as ['victim'] = honeypot_name
        self.msg_templete = {}
        
        # The message instance can define its own user, such as honeypot-abc.
        self.user = ''
    
    def put_msg(self, msg):
        # Avoid putting flood messages.
        msg['from'] = self.user
        msg_copy = msg.copy()
        msg_copy['timestamp'] = int(msg_copy['timestamp'])
        timestamp = (msg_copy['timestamp'])
        
        if not self.msg_record.has_key(timestamp):
            self.msg_record[timestamp] = []
        # Don't put the same message again in a second.
        if str(msg_copy) in self.msg_record[timestamp]:
            return
        self.msg_record[timestamp].append(str(msg_copy))
        
        
        self.msg_queue.put(msg)
        #TODO: send an event to notify the HCenter.
        
    def put_event(self, msg):
        msg['level'] = 'EVENT'
        self.put_msg(msg)
     
    def put_attack(self, msg):
        msg['level'] = 'ATTACK'
        self.put_msg(msg)
        
    def save_pcap(self, attack, pkt):
        hash_str = md5.md5(str(pkt)).hexdigest()
        #filename = "%s_%s.pcap" % (self.user, hash_str)
        filename = "%s.pcap" % hash_str
        location = './pcap/' + filename
        if not os.path.isfile(location):
            pcap_file = open(location, 'wb')
            hdr = self.__get_pcap_hdr() + self.__get_pcaprec_hdr(pkt)
            pcap_file.write(hdr)
            pcap_file.write(str(pkt))
            pcap_file.close()
        return filename
        
        # Build a new attack/event message entity.
    def new_msg(self, pkt, save_pcap = 1):
        msg = self.msg_templete.copy()
        msg['timestamp'] = pkt.time
        if save_pcap == 1:
            msg['pcap'] = self.save_pcap(msg, pkt)
        else:
            msg['pcap'] = 'None'
        return msg
