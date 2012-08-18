import threading, random, time
import message
    
class Analysis():

    def __init__(self, msg_queue, honeypots):
        self.msg_queue = msg_queue
        self.honeypots = honeypots
        
        self.dos_honeypots = {} #{honeypot_name: latest_timestamp}
        self.cancel_dos_timers = {} # {honeypot_name: timer}
        
        self.solicited_na_counter = 0
        self.solicited_targets = []
        self.regular_ns_timer = None
        self.regular_ns_dad_timer = None
        
    def __del__(self):
        # Cancel the timers.
        if self.regular_ns_timer != None:
            self.regular_ns_timer.cancel()
            for key, timer in self.cancel_dos_timers:
                if timer != None:
                    timer.cancel()
    
    def analyze(self, msg):
        if msg['type'] == "DAD" and msg['name'] == "Address in use":
            self.dos_new_ip6_handler(msg)
        elif msg['level'] == "EVENT" and msg['type'] == "NDP":
            self.parasite6_handler(msg)
        #elif
    
    # Active behavior that will enhance the capability of attack detection.
    def active_detection(self):
        self.regular_ns()
        self.regular_ns_dad()
    
    # Randomly choose a honeypot to send a Neighbor Solicitation for random target.
    def send_ns(self, dad_flag = False):
        target = "2002:" + ':'.join(''.join(str(time.time()).split('.'))[-7:])
        source = random.choice(self.honeypots.keys())
        retry = 1
        while not self.honeypots[source][1].isAlive() and retry < 5:
            source = random.choice(self.honeypots.keys())
            retry += 1
        if retry < 5:
            self.honeypots[source][1].send_NDP_NS(target, dad_flag)
            return target
        else:
            return None
    
    # Cancel the dos attacking alert of a honeypot after a timeout.
    def cancel_dos_state(self, hn_name):
        del self.dos_honeypots[hn_name]
    
    # Regularly send a Neighbor Solicitation message for DAD mechanism.
    def regular_ns_dad(self):
        target = self.send_ns(True)
        self.regular_ns_dad_timer = threading.Timer(10.0, self.regular_ns_dad)
        self.regular_ns_dad_timer.start()
        
    # Detect the THC-IPv6 dos-new-ip6 attacking.
    def dos_new_ip6_handler(self, msg):
        dos_count = len(self.dos_honeypots) + 1
        hn_len = len(self.honeypots)
        if dos_count >= 3 or dos_count > 1 and float(dos_count)/float(hn_len) > 0.5:
            # dos-new-ip6 attack
            # Modify the message and resubmit.
            msg['level'] = 'ATTACK'
            msg['from'] = 'Event Analysis Center'
            msg['type'] = 'DoS'
            msg['name'] = 'dos-new-ip6'
            msg['util'] = 'THC-IPv6: dos-new-ip6'
            self.msg_queue.put(msg)
        else:
            # Send another Neighbor Solicitation to confirm dos-new-ip6.
            self.send_ns(dad_flag = True)
        if self.dos_honeypots.has_key(msg['from']):
            self.cancel_dos_timers[msg['from']].cancel()
        self.dos_honeypots[msg['from']] = True
        self.cancel_dos_timers[msg['from']] = threading.Timer(10.0, self.cancel_dos_state, args = [msg['from']])
        self.cancel_dos_timers[msg['from']].start()
        return
    
    # Regularly send a Neighbor Solicitation to a random target.
    def regular_ns(self):
        if self.regular_ns_timer != None:
            self.regular_ns_timer.cancel()
        #print "send 1 ns"
        self.solicited_na_counter = 0
        target = self.send_ns()
        if target != None:
            self.solicited_targets.append(target)
        #global regular_ns_timer
        self.regular_ns_timer = threading.Timer(10.0, self.regular_ns)
        self.regular_ns_timer.start()
    
    # Detect the THC-IPv6: parasite6 attacking.
    def parasite6_handler(self, msg):
        if msg['target'] in self.solicited_targets:
            self.solicited_targets.remove(msg['target'])
            counter = self.solicited_na_counter
            counter += 1
            print "counter:" + str(counter)
            if counter >= 3:
                # parasite6
                msg['level'] = 'ATTACK'
                msg['from'] = 'Event Analysis Center'
                msg['type'] = 'MitM | DoS'
                msg['name'] = 'False answer to Neighbor Solicitation'
                msg['util'] = 'THC-IPv6: parasite6'
                self.msg_queue.put(msg)
            else:
                # send another NS to confirm if it is parasite6 attack.
                self.regular_ns()
                self.solicited_na_counter += counter
        
    def ndp_handler(self, msg):
        pass
