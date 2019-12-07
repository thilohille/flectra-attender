import signal
import sys
from time import sleep
import serial
import logging


#Raise exception on exit
def signal_handler(sig, frame):
        logging.info('shutting down')
        raise SystemExit('shutdown')

signal.signal(signal.SIGINT, signal_handler)        


class WifiScanner:
    def __init__(self, cfg):
        self.ser = serial.Serial(cfg["port"], cfg["baudrate"], timeout=1)  # open serial port
        
    def clearRxBuffer(self):
        logging.debug("clearRxBuffer start")
        while self.ser.in_waiting:
            line = self.ser.readline()
            logging.debug(line)
        logging.debug("clearRxBuffer done")
 
    def prepTxString(self, txstr):
        return bytes(txstr,'utf-8')+b'\0'
    
    def sendCmd(self, cmd, cmdparams=[], ack = False):
        logging.debug("sendCmd start (%s)"%(cmd))
        self.ser.write(self.prepTxString(cmd))
        for cmdparam in cmdparams:
            self.ser.write(self.prepTxString(cmdparam))
            sleep(0.1)
        line=""
        while (ack) & (line != "ACK-"+cmd):
            line = self.read()
            sleep(0.2)
        logging.debug("sendCmd done (%s)"%(cmd))
        
    def read(self):
        logging.debug("read start")
        line = self.ser.readline().decode("utf-8").rstrip()
        line = line.rstrip('\0')
        if (line[:22] == "Guru Meditation Error:"):
            raise WifiScannerCrash(line[23:])
        if len(line) > 0:
            logging.debug("read: "+line.rstrip('\0'))
        logging.debug("read done")
        return line
        
    def close(self):
        logging.debug("close start")
         # serial close port
        self.ser.close()
        logging.debug("close done")


class WifiScannerCrash(Exception):
    pass
