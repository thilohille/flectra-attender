#/usr/bin/python
import signal
import sys
from time import sleep
import json
import time
from io import StringIO
from flectraclient_rpc import FlectraClient
from shutil import copyfile
from wifiscanner import WifiScanner
import copy


DEBUG = False

def debug(data):
    if DEBUG:
        print(data, flush=True)


with open('config.json') as json_data_file:
    cfg = json.load(json_data_file)

scanner = WifiScanner(cfg["serial"])

data = {}
lasttimestamp = time.time()

scanner.sendCmd("stopscan",ack=True)

cfgsave = copy.deepcopy(cfg)
flag_config_changed = False
try:
    for i in cfg["user"]:
        sleep(0.1)
        scanner.clearRxBuffer()

        try:
            b = cfg["user"][i]["password"]
        except:
            scanner.sendCmd("decrypt",[cfg["user"][i]["password-encrypted"]])
            cfg["user"][i]["password"] = scanner.read()
            debug(i + ": " + cfg["user"][i]["password"])
        try:
            b = cfg["user"][i]["password-encrypted"]
        except:
            scanner.sendCmd("encrypt",[cfg["user"][i]["password"]])
            cfg["user"][i]["password-encrypted"] = scanner.read()
            debug(i + ": " + cfg["user"][i]["password-encrypted"])
            cfgsave["user"][i]["password-encrypted"] = cfg["user"][i]["password-encrypted"]
            del(cfgsave["user"][i]["password"])
            flag_config_changed = True
except (SystemExit):
    print("exiting")
    scanner.sendCmd("stopscan",ack=True)
    scanner.close()
    sys.exit(0)

scanner.clearRxBuffer()
debug(cfg["user"])

#do we have a a changed configuration?
if (flag_config_changed):
    debug("saving configuration") 
    #copy config file before replaceing it
    copyfile('config.json', 'config.json-backup')
    #create formatted json from cfgsave 
    formattedconfig = json.dumps(cfgsave,indent=4, separators=(',', ': '))
    #write it to config.json
    file = open("config.json","w") 
    file.write(formattedconfig)
    file.close

#tell device to start sending data
#handle shutdown

scanner.sendCmd("startscan",ack=True)

while True:
    try:
        line = scanner.read()
        debug(line)
        if len(line) == 0:
            sleep(0.2)
            continue
        try:
            obj = json.loads(line)
            #do we have a known mac-address?
            if (obj["m"] in cfg["user"]):
                #check if we have the record in memory, if not create it
                try:
                    mydata = data[obj['m']]
                except:
                    data[obj['m']] = {'lasttimestamp' : time.time(), "cfg" : cfg["user"][obj['m']]}
                    mydata = data[obj['m']]
                    #checkin flectra
                    print(obj['m'] + ": checkin", flush=True)
                    try:
                        flc = FlectraClient(data[obj['m']]["cfg"]["username"], data[obj['m']]["cfg"]["password"])
                        res = flc.attendance_checkin()
                    except:
                        print("Warning: unable to checkin!")
                obj['time'] = time.asctime( time.localtime(time.time()) )
                debug(data[obj['m']])
            else:
                #print("ignored mac " + obj['m'])
                pass
        except json.decoder.JSONDecodeError:
            print("jsonerrror: " + line)
            pass
        except:
            raise
        for i in data.copy():
            #user expired?
            if (time.time()-data[i]['lasttimestamp'] > data[i]["cfg"]["checkout-trigger-seconds"]):
                print(i + ": checkout", flush=True)
                try:
                    #checkout flectra
                    flc = FlectraClient(data[i]["cfg"]["username"], data[i]["cfg"]["password"])
                    res = flc.attendance_checkout()
                except:
                    print("Warning: unable to checkout!")
                debug(data[i])
                del data[i]
        sleep(0.02)
    except (SystemExit):
        print("exiting")
        scanner.sendCmd("stopscan",ack=True)
        scanner.close()
        sys.exit(0)

