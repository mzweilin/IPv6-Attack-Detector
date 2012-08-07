import time

class Log:
    # Print level: 0: Least messages, for Monitor; 1:Medium messages, for Diagnosis; 2: Most messages, for Debug.
    print_level = 0
    
    def __init__(self, filename):
        self.filename = filename
        self.log = open(self.filename, 'a')
        
    def write(self, msg, level = 0):
        timestamp = time.asctime()
        record = "[%d][%s] %s\n" % (level, timestamp, msg)
        self.log.write(record)
        if level <= self.print_level:
            print msg
            
    def set_print_level(self, level):
        self.print_level = level
        
    def close(self):
        self.log.close()

