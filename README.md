# flectra-attender
does automatically checkin/out on flectras hr.attendance app based on visible wifi mac-addresses.

# How it works
flectra-attender.py is run on a network-computer connected to a esp32 board by usb-serial .
ESP32WifiScanner is run on the esp32-board and scans all wifi-channels sequentially for mac-addresses and 
writes the collected addresses to usb-serial.
flectra-attender looks up all mac-addresses in the configuration-files for matches and check them in with flectra hr.attendance
using flectras RPC-api.
For each user in the key "checkout-trigger-seconds" can be set. After that amount of seconds absence of the mac-address
the user is considered "away" and the checkout will be done.

# Security
The flectra RPC-api requires the login credentials to do checkin/checkout-operations, therefore the username and password
have to be saved in the config.json file.
To avoid that all cleartext passwords found in the configuration are being replaced by encrypted aes-ecb passwords, encrypted by
the esp32. The key is set by compiletime in the file "ESP32WifiScanner.ino".

# Is this more secure than cleartext passwords in the configuration file? 
i am not a security expert so **propably it is not** :-)
The cleartext passwords are send unencrypted via usb on startup, so they are pretty easy to intercept,
physically access assumed.
They are also currently stored in the memory during the runtime of flectra-attender.py.
Also the cleartext-passwords may be recoverable from the memory of the esp32.
