"""
InfoBlox WAPI Documentation:
https://infoblox.domain.local/wapidoc/

This is used to take a single file of IP addresses and MAC addresses 
and created fixed IPs within InfoBlox.
"""

import requests
import urllib3
import json
import getpass
import os
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.exit()  # delete me after you update stuff below.


#####
if os.name == "nt":
    path = "c:/path/to/stuff/and/things"
else:
    path = "/mnt/c/path/to/stuff/and/things"
input_file = "InfoBloxFixedAddressImport.csv" # ip_address,mac_address
input_full_path = os.path.join(path, input_file)
error_file = "InfoBloxError.txt"
error_full_path = os.path.join(path, error_file)

url = 'https://infoblox.domain.local/wapi/v2.11.3/'
headers = {'Content-type': 'application/json'}
#####

# clear previous error log.
open(error_full_path, 'w').close() 


def InfoBloxAuthentication():
    username = input("[>]\tEnter your username: ")
    password = getpass.getpass("[>]\tEnter your password: ")
    print("[!]\tWaiting for Authentication...")
    
    infoblox = requests.Session()
    infoblox.auth = (username, password)
    infoblox.verify = False
    return infoblox

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
    with open(input_full_path, 'r') as f:
        text = f.read().splitlines()

    infoblox = InfoBloxAuthentication()

    for line in text:
        ip, mac = line.split(',')
        data = { 'ipv4addr' : ip, 'mac': mac}

        r = infoblox.post(url + "fixedaddress", json=data, headers=headers, verify=False)
        if r.status_code == 400:
            error_log = open(error_full_path, 'a')
            error_log.write(f"[!]\t{ip}\n")
            error_log.close()
            print(f"[!]\t{ip} Fixed IP Failed") # Could be because it's reserved or out of scope
        if r.status_code == 201:
            print(f"[i]\t{ip} Fixed IP Created")

    restartInfoBlox(infoblox)


if __name__ == "__main__":
    main()
