"""
InfoBlox WAPI Documentation:
https://infoblox.domain.local/wapidoc/

Used to create a single fixed IP from input prompts
or via arguments passed to the script.

usage: new_fixed_ip.py [-h] -i IPADDRESS -m MAC [-y]

Create fixed IP and MAC Address in InfoBlox passed via CLI   

options:
  -h, --help            show this help message and exit      
  -i IPADDRESS, --ipaddress IPADDRESS
                        IP address to create
  -m MAC, --mac MAC     mac address to bind
  -y                    send to InfoBlox without confirmation  
"""

import requests
import urllib3
import json
import getpass
import os
import sys
import re
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = 'https://infoblox.domain.local/wapi/v2.11.3/'
headers = {'Content-type': 'application/json'}

def clear():
    os.system("cls") if os.name == "nt" else os.system("clear")

def InfoBloxAuthentication():
    """
    This function contains input for username and password to pass to 
    InfoBlox, creates a session (as infoblox) once authentication occurs
    """
    username = input("[>]\tEnter your username: ")
    password = getpass.getpass("[>]\tEnter your password: ")
    print("[!]\tWaiting for Authentication...")

    infoblox = requests.Session()
    infoblox.auth = (username, password)
    infoblox.verify = False
    infoblox.get(url, verify=False)
    return infoblox

def IP_MAC_Args():
    """
    This is called if there are arguments passed to the script via cli,
    and assigns and returns the variables ip and mac to the script.
    """
    parser = argparse.ArgumentParser(description='Create fixed IP and MAC Address in InfoBlox passed via CLI')
    parser.add_argument('-i', '--ipaddress', type=str, help='IP address to create', required=True)
    parser.add_argument('-m', '--mac', type=str, help='mac address  to bind', required=True)
    parser.add_argument('-y', action='store_true', help='send to InfoBlox without confirmation', required=False)
    args = parser.parse_args()
    ip = args.ipaddress
    mac = args.mac
    confirm = args.y
    return ip, mac, confirm

def isValidIPAddress(ip):
    """
    Input is an IP as a string, and we regex it to make sure it's a valid 
    IP address, and then it looks at the last octet to see if it == 255.
    If it's true, then we return True, otherwInfoBlox we print a message and exit.

    >>> isValidIPAddress("1.1.1.1")
    True

    """
    pattern = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if re.search(pattern, ip):
        if ip[-3:] == "255":
            return False
    else:
        return False
    return True

def isValidMACAddress(mac):
    """
    Input is a MAC address as a string, and we regex it to make sure it's a valid
    MAC address, and return True or False.

    >>> isValidMACAddress("FE-89-D2-16-0D-C9")
    True

    """
    pattern = ("^([0-9A-Fa-f]{2}[\\.:-]){5}([0-9A-Fa-f]{2})|" +
             "([0-9a-fA-F]{4}[\\.:-][0-9a-fA-F]{4}[\\.:-][0-9a-fA-F]{4})$")
    p = re.compile(pattern)
    if (str == None): return False
    return True if re.search(p, mac) else False

def formatMACAddressforInfoBlox(mac):
    """
    We take the MAC once it's passed regex check, and instead of making 
    the user format the mac or even check the format, we just strip it down 
    and reformat it regardless of how it's sent so that it is correct for InfoBlox. 

    >>> formatMACAddressforInfoBlox("FE-89-D2-16-0D-C9")
    FE:89:D2:16:0D:C9

    >>> formatMACAddressforInfoBlox("FE.89.D2.16.0D.C9")
    FE:89:D2:16:0D:C9    

    >>> formatMACAddressforInfoBlox("FE:89:D2:16:0D:C9")
    FE:89:D2:16:0D:C9

    >>> formatMACAddressforInfoBlox("FE89.D216.0DC9")
    FE:89:D2:16:0D:C9

    >>> formatMACAddressforInfoBlox("FE89:D216:0DC9")
    FE:89:D2:16:0D:C9

    >>> formatMACAddressforInfoBlox("FE89-D216-0DC9")
    FE:89:D2:16:0D:C9

    """
    m = ""
    for x in mac:
        if x.isalnum():
            m += x
    if len(m) != 12:
        print(f"[!]\t{mac} - Invalid MAC Address (Incorrect Length)\n\n")
        sys.exit()
    mac = f"{m[0:2]}:{m[2:4]}:{m[4:6]}:{m[6:8]}:{m[8:10]}:{m[10:]}"
    return mac.lower()

def sendtoInfoBlox(ip, mac, infoblox):
    data = {'ipv4addr' : ip, 'mac': mac}

    r = infoblox.post(url + "fixedaddress", json=data, headers=headers, verify=False)
    if r.status_code == 400:
        print(f"[!]\t{ip} Fixed IP Failed") # Could be because it's reserved or out of scope
    if r.status_code == 201:
        print(f"[i]\t{ip} Fixed IP Created")
    return

def restartInfoBlox(infoblox):
    data = '{"restart_option": "RESTART_IF_NEEDED", "service_option": "ALL", "member_order": "SEQUENTIALLY", "sequential_delay": 5}'
    get_grid = infoblox.get(url + 'grid', headers=headers, verify=False)
    get_grid = get_grid.text
    get_grid = json.loads(get_grid)
    grid = get_grid[0]['_ref']
    restart = infoblox.post(url + grid + '?_function=restartservices', data=data, headers=headers, verify=False)
    if restart.status_code == 200:
        print("[i]\tRestart was requested")
    else:
        print(restart.text)
    return

def main():
    clear()

    if len(sys.argv) > 3:   # hopefully the args are passed correctly
        ip, mac, confirm = IP_MAC_Args() 
    elif len(sys.argv) > 1: # will simply send help to the user
        IP_MAC_Args() 
    else:   # promp for inputs
        confirm = False
        ip = input("\n\n[>]\tIP Address: ")
        mac = input("[>]\tMAC Address: ")

    infoblox = InfoBloxAuthentication()

    # Is the IP we are given look correct?
    if isValidIPAddress(ip):
        pass
    else:
        print(f"[!]\t{ip} - Invalid IP Address\n\n")
        sys.exit()


    # Is the MAC we are given look correct?
    if isValidMACAddress(mac):
        # If so, reformat it for InfoBlox Fixed IP
        mac = formatMACAddressforInfoBlox(mac)
    else:
        print(f"[!]\t{mac} - Invalid MAC Address\n\n")
        sys.exit()

    
    """
    If you pass arguments to the script, and do not tell us to not confirm we ask
    you to confirm to commit to InfoBlox, and if you do then we send it without confirmation
    """
    if not confirm:
        print(f"\nConfirm the following is correct:\n\n[i]\tIP Address: {ip}\n[i]\tMAC: {mac}\n\n")
        send_it = input("Do you wish to send this to InfoBlox? (y/n): ")
        if send_it.lower() == "y":
            sendtoInfoBlox(ip, mac, infoblox)
        else:
            print("Did not receive confirmation, exiting...")
            sys.exit()
    else:
        sendtoInfoBlox(ip, mac, infoblox)

    # Restart service if necessary (usually is for fixed IPs)
    restartInfoBlox(infoblox)


if __name__ == "__main__":
    main()