import signal
import sys
from time import sleep
import serial

DEBUG = False

def debug(data):
    if DEBUG:
        print(data, flush=True)

#Raise exception on exit
def signal_handler(sig, frame):
        print('shutting down')
        raise SystemExit('shutdown')

signal.signal(signal.SIGINT, signal_handler)        


class WifiScanner:
    def __init__(self, cfg):
        self.ser = serial.Serial(cfg["port"], cfg["baudrate"], timeout=1)  # open serial port
        
    def clearRxBuffer(self):
        debug("clearRxBuffer start")
        while self.ser.in_waiting:
            line = self.ser.readline()
            debug(line)
        debug("clearRxBuffer done")
 
    def prepTxString(self, txstr):
        return bytes(txstr,'utf-8')+b'\0'
    
    def sendCmd(self, cmd, cmdparams=[], ack = False):
        debug("sendCmd start (%s)"%(cmd))
        self.ser.write(self.prepTxString(cmd))
        for cmdparam in cmdparams:
            self.ser.write(self.prepTxString(cmdparam))
            sleep(0.1)
        line=""
        while (ack) & (line != "ACK-"+cmd):
            line = self.read()
            sleep(0.2)
        debug("sendCmd done (%s)"%(cmd))
        
    def read(self):
        debug("read start")
        line = self.ser.readline().decode("utf-8").rstrip()
        debug(line.rstrip('\0'))
        debug("read done")
        return line.rstrip('\0')

    def close(self):
        debug("close start")
         # serial close port
        self.ser.close()
        debug("close done")
