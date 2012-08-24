#!/usr/bin/env python
import os, threading, time, sys
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

class SixGuard():
    
    def __init__(self):
        # Log
        attack_log_filename = os.path.join(log_dir, "attack.log")
        self.attack_log = logger.Log(attack_log_filename, auto_timestamp = 0)
        self.attack_log.set_print_level(3) # Only print the attacking message but not the event message.
        
        center_log_filename = os.path.join(log_dir, "center.log")
        self.center_log = logger.Log(center_log_filename)
        
        # Honeypots and Globalpot
        self.honeypots = {} #{'name'-> [conf, thread_instance]}
        self.globalpot_cfg = None
        
        # Message management
        self.msg_queue = Queue()
        
        self.msg_handler = threading.Thread(target = self.handle_msg)
        self.msg_handler.setDaemon(True)
        self.msg_handler.start()
        
        # Handle the event message, sometimes will generate an attack message.
        self.event_handler = event.Analysis(self.msg_queue, self.honeypots)
        
    def __del__(self):
        self.attack_log.close()
        self.center_log.close()
    
    
    # Display, log, analyze, and report the EVENT/ATTACK messages.
    def handle_msg(self):
        while True:
            if self.msg_queue.qsize() > 0:
                msg = self.msg_queue.get()
                if msg['level'] == 'EVENT' and self.event_handler != None:
                    self.event_handler.analyze(msg)
                    self.attack_log.warning(self.format_msg(msg))
                else:
                    self.attack_log.alert(self.format_msg(msg))
            time.sleep(1)
            #TODO: use event to get notification.
    
    # Loade the configuration files of honeypots and globalpot.
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
                        self.center_log.error(str(err))
                        continue
                    self.center_log.info("Configuration file <%s> loaded." % conf_file)
                    
                    if config.config['name'] == "Globalpot":
                        self.globalpot_cfg = config.config.copy()
                    else:
                        honeypot_cfg = config.config.copy()
                        name = honeypot_cfg['name']
                        if self.honeypots.has_key(name):
                            self.center_log.warning("Duplicate name of honeypots: %s\n", name)
                        else:
                            self.honeypots[name] = [honeypot_cfg, None]
                    config.config.clear()
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
        if self.globalpot_cfg != None:
            gp = Globalpot(self.globalpot_cfg, self.msg_queue)
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
        if msg.has_key('tgt'):
            msg_str += "Target [%s]\n" % msg['tgt']
        if msg.has_key("src"):
            msg_str += "Source: [%s]" % msg['src']
            if msg.has_key("lladdr"):
                msg_str += "  MAC: %s (%s)" % (msg['lladdr'], mac2vendor(msg['lladdr']))
            msg_str += "\n"
        msg_str += "Utility: %s\n" % msg['util']
        msg_str += "Packets: %s\n" % msg['pcap']
        return msg_str
        
def main():
    sixguard = SixGuard()
    sixguard.load_config()
    if len(sixguard.honeypots) == 0:
        print "No honeypot configuration files found."
        print "Please run `sudo ./conf_generator.py` to create some."
        sys.exit()
    if sixguard.globalpot_cfg == None:
        print "No globalpot configuration filel found."
        print "Please run `sudo ./conf_generator.py` to create one."
        sys.exit()
    sixguard.start_all_honeypots()
    sixguard.start_globalpot()
        
    if sixguard.event_handler != None:
        sixguard.event_handler.active_detection()
        
    try:
        raw_input("SixGuard is running...\nPress <Ctrl>+Z to stop.\n")
    except KeyboardInterrupt:
        sixguard.stop_all_honeypots()
        del sixguard
            
if __name__ == "__main__":
    main()
