#/usr/bin/python
import signal
import sys
from io import StringIO
import copy
import time
import json
from flectraclient_rpc import FlectraClient
from shutil import copyfile
from wifiscanner import WifiScanner,WifiScannerCrash
import logging

DEBUG = True

if DEBUG:
    #logging.basicConfig( level=logging.DEBUG, filename='flectra-attender.log')
    logging.basicConfig( level=logging.DEBUG)    
else:
    #logging.basicConfig( level=logging.INFO, filename='flectra-attender.log')
    logging.basicConfig( level=logging.INFO)    

with open('config.json') as json_data_file:
    cfg = json.load(json_data_file)

scanner = WifiScanner(cfg["serial"])

data = {}
lasttimestamp = time.time()

scanner.sendCmd("stopscan",ack=True)
logging.info("reading config.json")
cfgsave = copy.deepcopy(cfg)
flag_config_changed = False
try:
    for i in cfg["user"]:
        time.sleep(0.1)
        scanner.clearRxBuffer()

        try:
            b = cfg["user"][i]["password"]
        except:
            if len(cfg["user"][i]["password-encrypted"].strip()) % 4 != 0:
                logging.warning(i + ": encrypted password is not base64, removing user: " + cfg["user"][i]["username"])
                cfg["user"][i]["active"] = False
                continue
            scanner.sendCmd("decrypt",[cfg["user"][i]["password-encrypted"]])
            try:
                cfg["user"][i]["password"] = scanner.read()
                cfg["user"][i]["active"] = True
                logging.debug(i + ": " + cfg["user"][i]["password"])
            except (UnicodeDecodeError):
                logging.debug(i + ": could not decrypt password, removing user: " + cfg["user"][i]["username"])
                cfg["user"][i]["active"] = False
                
        try:
            b = cfg["user"][i]["password-encrypted"]
        except:
            scanner.sendCmd("encrypt",[cfg["user"][i]["password"]])
            cfg["user"][i]["password-encrypted"] = scanner.read()
            cfg["user"][i]["active"] = True
            logging.debug(i + ": " + cfg["user"][i]["password-encrypted"])
            cfgsave["user"][i]["password-encrypted"] = cfg["user"][i]["password-encrypted"]
            del(cfgsave["user"][i]["password"])
            flag_config_changed = True
    
except (SystemExit):
    logging.info("exiting")
    scanner.sendCmd("stopscan",ack=True)
    scanner.close()
    sys.exit(0)

scanner.clearRxBuffer()
logging.debug(cfg["user"])

#do we have a a changed configuration?
if (flag_config_changed):
    #copy config file before replaceing it
    if (DEBUG):
        print("coping config.json -> config.json-backup")
        copyfile('config.json', 'config.json-backup')
    #create formatted json from cfgsave 
    formattedconfig = json.dumps(cfgsave,indent=4, separators=(',', ': '))
    #write it to config.json
    print("new passwords found, saving configuration") 
    file = open("config.json","w") 
    file.write(formattedconfig)
    file.close

#tell device to start sending data
#handle shutdown
logging.info("starting wifi-scanner") 
scanner.sendCmd("startscan",ack=True)
logging.info("now scanniing....") 

while True:
    try:
        line = scanner.read()
        if len(line) == 0:
            time.sleep(0.2)
            continue
        logging.debug(line)
        try:
            obj = json.loads(line)
            #do we have a known mac-address?
            if (obj["m"] in cfg["user"] and  cfg["user"][obj["m"]]["active"]):
                #check if we have the record in memory, if not create it
                try:
                    mydata = data[obj['m']]
                except:
                    scanner.sendCmd("checkin",ack=True)
                    data[obj['m']] = {'lasttimestamp' : time.time(), "cfg" : cfg["user"][obj['m']]}
                    mydata = data[obj['m']]
                    #checkin flectra
                    print(obj['m'] + ": checkin user " + data[obj['m']]["cfg"]["username"], flush=True)
                    try:
                        flc = FlectraClient(data[obj['m']]["cfg"]["username"], data[obj['m']]["cfg"]["password"])
                        res = flc.attendance_checkin()
                    except:
                        logging.warning("Warning: unable to checkin!")
                obj['time'] = time.asctime( time.localtime(time.time()) )
                logging.debug(data[obj['m']])
            else:
                #print("ignored mac " + obj['m'])
                pass
        except json.decoder.JSONDecodeError:
            logging.warning("jsonerrror: " + line)
            pass
        except:
            raise
        for i in data.copy():
            #user expired?
            if (time.time()-data[i]['lasttimestamp'] > data[i]["cfg"]["checkout-trigger-seconds"]):
                scanner.sendCmd("checkout",ack=True)
                logging.info(i + ": checkout user " + data[i]["cfg"]["username"], flush=True)
                try:
                    #checkout flectra
                    flc = FlectraClient(data[i]["cfg"]["username"], data[i]["cfg"]["password"])
                    res = flc.attendance_checkout()
                except:
                    logging.warning("Warning: unable to checkout!")
                logging.debug(data[i])
                del data[i]
        time.sleep(0.02)
    except (SystemExit):
        logging.info("exiting")
        scanner.sendCmd("stopscan",ack=True)
        scanner.close()
        sys.exit(0)

