#/usr/bin/python
import signal
import sys, getopt, copy
import time, logging
from io import StringIO
import json
from flectraclient_rpc import FlectraClient
from shutil import copyfile
from wifiscanner import WifiScanner,WifiScannerCrash


def loadconfig(scanner, cfg, config_file):
    global DEBUG
    data = {}
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
                    logging.warning(i + ": could not decrypt password, removing user: " + cfg["user"][i]["username"])
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
        file = open(config_file,"w") 
        file.write(formattedconfig)
        file.close
    return data

def scan(scanner, cfg, data):
    lasttimestamp = time.time()

    #tell device to start sending data
    #handle shutdown
    logging.info("starting wifi-scanner") 
    scanner.sendCmd("startscan",ack=True)
    logging.info("now scanning....") 

    while True:
        try:
            line = scanner.read()
            if len(line) == 0:
                time.sleep(0.2)
                continue
            #logging.info(line)
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
                        logging.info(obj['m'] + ": checkin user " + data[obj['m']]["cfg"]["username"])
                        try:
                            flc = FlectraClient(data[obj['m']]["cfg"]["username"], data[obj['m']]["cfg"]["password"])
                            res = flc.attendance_checkin()
                        except:
                            logging.warning("Warning: unable to checkin!")
                    data[obj['m']]["lasttimestamp"] = time.time()
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
                    logging.info(i + ": checkout user " + data[i]["cfg"]["username"])
                    try:
                        #checkout flectra
                        flc = FlectraClient(data[i]["cfg"]["username"], data[i]["cfg"]["password"])
                        res = flc.attendance_checkout()
                    except:
                        logging.warning("Warning: unable to checkout!")
                    logging.debug(data[i])
                    del data[i]
                else:
                    if (data[i].get("lastlogged",data[i]["lasttimestamp"]) != data[i]["lasttimestamp"]):
                        logging.info(i + ": user " + data[i]["cfg"]["username"] + " is still around, awaytime: " + str(int(time.time()-data[i]['lastlogged'])) + " seconds")
                    data[i]["lastlogged"] = data[i]["lasttimestamp"]
            time.sleep(0.02)
        except (SystemExit):
            logging.info("exiting")
            scanner.sendCmd("stopscan",ack=True)
            scanner.close()
            sys.exit(0)

DEBUG = False

def main(argv):
    global DEBUG
    config_file = 'config.json'
    try:
        opts, args = getopt.getopt(argv,"hdc:",["debug","config="])
    except getopt.GetoptError:
        print('flectra-attender.py -d -c <filename>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('flectra-attender.py -d -c <filename>')
            print(' -d                  Enable debug output. Also a backup of the configuration will be made before overwriting.')
            print(' -c <filename>       Alternative configuration file. default: "config.json"')
            sys.exit()
        elif opt in ("-d", "--debug"):
            DEBUG = True
        elif opt in ("-c", "--config"):
            config_file = arg
    if DEBUG:
        logging.basicConfig(format='%(asctime)s %(levelname)-2s %(message)s', 
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S')    
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)-2s %(message)s', 
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S')  
          
    with open(config_file) as json_data_file:
        cfg = json.load(json_data_file)
    scanner = WifiScanner(cfg["serial"])
    data = loadconfig(scanner, cfg, config_file)
    scan(scanner, cfg, data)
    
if __name__ == "__main__":
   main(sys.argv[1:])
