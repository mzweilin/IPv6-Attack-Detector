import time

class Log:
    print_level = 0
    msg_level = {0: 'DEBUG', 1: 'INFO', 2: 'WARNING', 3: 'ALERT'}
    
    def __init__(self, filename, auto_timestamp = 1):
        self.filename = filename
        self.log = open(self.filename, 'a')
        self.auto_timestamp = auto_timestamp
        
    def write(self, msg, level = 0):
        try:
            if level >= self.print_level:
                print msg
            #msg = msg.replace('\n', "\\n")
            if self.auto_timestamp == 1:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                record = "%s %s %s\n" % (timestamp, self.msg_level[level], msg)
                self.log.write(record)
            else:
                self.log.write(msg)
        except KeyboardInterrupt:
            self.close()

    def debug(self, msg):
        self.write(msg, 0)
    def info(self, msg):
        self.write(msg, 1)
    def warning(self, msg):
        self.write(msg, 2)
    def alert(self, msg):
        self.write(msg, 3)
            
    def set_print_level(self, level):
        self.print_level = level
        
    def close(self):
        self.log.close()
