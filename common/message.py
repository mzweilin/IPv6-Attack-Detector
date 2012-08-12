import os
import md5

class Message():
    def __init__(self, msg_queue):
        self.msg_queue = msg_queue
        
        # Avoid putting flood msgs.
        self.msg_record = {} # {timestamp: [str(msg)]}
        
        # The message instance can define its own message templete. Such as ['victim'] = honeypot_name
        self.msg_templete = {}
        
        # The message instance can define its own user, such as honeypot-abc.
        self.user = ''
    
    def put_msg(self, msg):
        # Avoid putting flood messages.
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
        filename = "%s_%s.pcap" % (self.user, hash_str)
        location = './pcap/' + filename
        if not os.path.isfile(location):
            pcap_file = open(location, 'wb')
            pcap_file.write(str(pkt))
            pcap_file.close()
        return filename
        
        # Build a new attack/event message entity.
    def new_msg(self, pkt):
        msg = self.msg_templete.copy()
        msg['timestamp'] = pkt.time
        msg['pcap'] = self.save_pcap(msg, pkt)
        return msg
