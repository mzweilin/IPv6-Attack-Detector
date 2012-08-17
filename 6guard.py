#!/usr/bin/env python
import os, threading, time
from Queue import Queue
from common import logger
from common.honeypot import Honeypot
from common.globalpot import Globalpot
import ConfigParser
from common import config
from common.common import *
from common import event

conf_dir = "./conf"
log_dir = "./log"
pcap_dir = "./pcap"
    
# Honeypot Center
class HCenter():
    msg_queue = Queue()
    honeypots = {} #{'name'-> [conf, thread_instance]}
    
    # Log
    attack_log = None
    center_log = None
    
    def __init__(self):
        attack_log_filename = os.path.join(log_dir, "attack.log")
        self.attack_log = logger.Log(attack_log_filename, auto_timestamp = 0)
        center_log_filename = os.path.join(log_dir, "center.log")
        self.center_log = logger.Log(center_log_filename)
        
        self.msg_handler = threading.Thread(target = self.handle_msg)
        self.msg_handler.setDaemon(True)
        self.msg_handler.start()
        
        self.event_handler = event.Analysis(self.msg_queue, self.honeypots)
        
    def __del__(self):
        self.attack_log.close()
        self.center_log.close()
        
    def handle_msg(self):
        #Display
        #Log
        #Analisis
        #Report
        
        while True:
            if self.msg_queue.qsize() > 0:
                msg = self.msg_queue.get()
                self.attack_log.info(self.format_msg(msg))
                self.event_handler.analyze(msg)
            time.sleep(1)
            #TODO: use event to get notification.
            
    # Generate the honeypot configuration files.
    def generate_config(self):
        pass
    
    # Loade the configuration files of honeypot.
    def load_config(self):
        cfg = ConfigParser.SafeConfigParser()
        for parent, dirnames, filenames in os.walk(conf_dir):
            for filename in filenames:
                split_name = filename.split('.')
                if len(split_name) == 2 and split_name[1] == 'ini':
                    conf_file = os.path.join(parent, filename)
                    cfg.read(conf_file)
                    try:
                        config.parse_config(cfg)
                    except config.ParsingError, err:
                        self.center_log.errer(str(err))
                        continue
                    self.center_log.info("Configuration file <%s> loaded." % conf_file)
                    
                    honeypot_cfg = config.config.copy()
                    config.config.clear()
                    
                    name = honeypot_cfg['name']
                    if self.honeypots.has_key(name):
                        self.center_log.warning("Duplicate name of honeypots: %s\n", name)
                    else:
                        self.honeypots[name] = [honeypot_cfg, None]
        return
    
    
    # Sent commands to honeypot.
    # STATUS, START, STOP, RESTART
    def send_command(self, name, command):
        if not self.honeypots.has_key(name):
            self.center_log.error("Send a command [%s] to an unexist honeypot [%s].", (command,name))
            return False
        cfg, hp = self.honeypots[name]
        if command == "START":
            if hp == None:
                hp = Honeypot(cfg, self.msg_queue)
                hp.setDaemon(True)
                hp.start()
                self.honeypots[name][1] = hp
                self.center_log.info("[%s] starts." % name)
            return True
        elif command == "STOP":
            if hp != None:
                hp.stop = True
                hp.__del__()
                hp = None
                self.center_log.info("[%s] stops." % name)
            return True
        else:
            self.center_log.error("Send an unknown command [%s] to [%s]", command, name)
            return False
    
    def start_all_honeypots(self):
        for cfg, hp in self.honeypots.values():
            if hp == None:
                self.send_command(cfg['name'], "START")
        return
    
    def stop_all_honeypots(self):
        for cfg, hp in self.honeypots.values():
            if hp != None:
                self.send_command(cfg['name'], "STOP")
        return
            
    def start_globalpot(self):
        gp = Globalpot(self.msg_queue)
        gp.setDaemon(True)
        gp.start()
        return
    
    def format_msg(self, msg):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(msg['timestamp']))
        
        msg_str = "\n[%s]\n" % msg['level']
        msg_str += "Timestamp: %s\n" % time_str
        msg_str += "Reported by: %s\n" % msg['from']
        msg_str += "Type: %s\n" % msg['type']
        msg_str += "Name: %s\n" % msg['name']
        if msg['level'] == 'ATTACK':
            msg_str += "Attacker: [%s]" % msg['attacker']
            if msg.has_key("attacker_mac"):
                msg_str += "  %s (%s)\n" % (msg['attacker_mac'], mac2vendor(msg['attacker_mac']))
            else:
                msg_str += '\n'
            msg_str += "Victim  : [%s]" % msg['victim']
            if msg.has_key("victim_mac"):
                msg_str += "  %s (%s)\n" % (msg['victim_mac'], mac2vendor(msg['victim_mac']))
            else:
                msg_str += '\n'
        msg_str += "Utility: %s\n" % msg['util']
        msg_str += "Packets: %s\n" % msg['pcap']
        return msg_str
        
def main():
    sixguard = HCenter()
    sixguard.load_config()
    sixguard.start_all_honeypots()
    sixguard.event_handler.active_detection()
    #sixguard.start_globalpot()
    
    try:
        raw_input("SixGuard is running...\n")
    except KeyboardInterrupt:
        sixguard.stop_all_honeypots()
        del sixguard
            
if __name__ == "__main__":
    main()
