"""
InfoBlox WAPI Documentation:
https://infoblox.domain.local/wapidoc/

This takes the error file from the import (fixed_file_import.py)
and queries InfoBlox as to why it failed.
Prints to stdout and writes to the output file below.
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
input_file = "InfoBloxError.txt" 
input_full_path = os.path.join(path, input_file)
output_file = "InfoBloxIPErrorReason.txt"
output_full_path = os.path.join(path, output_file)

url = "https://infoblox.domain.local/wapi/v2.11.3/ipv4address?ip_address="
headers = {'Content-type': 'application/json'}

# types of IPs used in InfoBlox
type_of_usage = ["FA", "DHCP_RANGE", "RESERVED"]
#####

# clear previous error log.
open(output_full_path, 'w').close() 


def InfoBloxAuthentication():
    username = input("[>]\tEnter your username: ")
    password = getpass.getpass("[>]\tEnter your password: ")
    print("[!]\tWaiting for MFA...")
    
    infoblox = requests.Session()
    infoblox.auth = (username, password)
    infoblox.verify = False
    return infoblox


def log_it(message, prnt=True):
    with open(output_full_path, 'a') as f:
        if prnt:
            print(message, end='')
        f.write(message)


def main():
    with open(input_full_path, 'r') as f:
        text = f.read().splitlines()
    
    infoblox = InfoBloxAuthentication()

    for ip in text:
        r = infoblox.get(url + ip, headers=headers, verify=False)
        json_data = json.loads(r.content)
        if r.status_code == 200:
            for resp in json_data:
                network = resp.get("network")
                mac = resp.get("mac_address")
                log_it(f"[i]\t{ip} belongs to {network}\n")
                if any(x in resp.get("types") for x in type_of_usage):
                    if "DHCP_RANGE" in resp.get("types"):
                        log_it(f"[i]\t{ip} is in DHCP range for {network}\n")
                    if "FA" in resp.get("types"):
                        log_it(f"[i]\t{ip} is binded to {mac} as a Fixed address.\n")
                    if "RESERVATION" in resp.get("types"):
                        log_it(f"[i]\t{ip} is a DHCP RESERVED address.\n")
                    else:
                        log_it(f"[i]\t{ip} doesn't appear to be in use as a Range/Fixed address or Reservation object.\n")
                else:
                    log_it(f"[i]\tHTTP response code: {r.status_code}.\n[i]\tIt appears that the IPv4 object doesn't exist in any of the configured grid networks.\n")

            log_it("\n", prnt=False)    # new line and if we want stdout, make it false.


if __name__ == "__main__":
    main()