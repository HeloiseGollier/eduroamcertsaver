#!/usr/bin/env python3
import json
import signal
import os
import subprocess
import time
import re
from pathlib import Path
import argparse


parser = argparse.ArgumentParser()
parser.add_argument(
    "dongle",
    help="Wireless interface name (e.g. wlx001122334455). Use command ifconfig -a to find your dongle ID."
)
args = parser.parse_args()

dongle_id = args.dongle
print(f"Dongle: {dongle_id}")

cmd = f"sudo ./../wpa_supplicant/wpa_supplicant -D nl80211 -i {dongle_id} -c client.conf"
down_interface_cmd = f'sudo ip link set dev {dongle_id} down'
change_address_cmd = f'sudo ip link set dev {dongle_id} address'
up_interface_cmd = f"sudo ip link set dev {dongle_id} up"
restart_wpa_supplicant = 'sudo pkill wpa_supplicant'


issuers_directory = Path("scrapedissuers")

if not issuers_directory.exists():
    issuers_directory.mkdir(parents=True)
    print("Issuers directory created.")
else:
    print("Issuers directory already exists, not creating a new one.")

leaf_directory = Path("scrapedcerts")

if not leaf_directory.exists():
    leaf_directory.mkdir(parents=True)
    print("Issuers directory created.")
else:
    print("Leaf certificate directory already exists, not creating a new one.")


# Periodically switch MAC addresses between each connection.
def generate_mac_list(n, prefix="14:05:0f:9e"):
    base = prefix.split(":")
    base_int = int("".join(base), 16)

    macs = []
    for i in range(1, n):
        mac_int = base_int << 16 | i
        mac_hex = f"{mac_int:012x}"
        mac = ":".join(mac_hex[j:j + 2] for j in range(0, 12, 2))
        macs.append(mac)

    return macs

with open('../../eduroamcrawler/realms.json') as f:
    realms = json.load(f)
mac_list = generate_mac_list(len(realms) + 1)

for i in range(len(realms)):
    print(i)
    realm = realms[i]
    file_path = 'client.conf'
    param = 'identity'
    new_value = '@' + realm
    print(new_value)

    with open(file_path, 'r') as file:
        content = file.read()

        content = re.sub(rf'{param}="[^"]+"', f'{param}="{new_value}"', content)
        with open(file_path, 'w') as writefile:
            writefile.write(content)

    changemac = f"{change_address_cmd} {mac_list[i]}"
    print(changemac)
    subprocess.Popen(down_interface_cmd, shell=True, preexec_fn=os.setsid)
    time.sleep(1.5)
    subprocess.Popen(changemac, shell=True, preexec_fn=os.setsid)
    time.sleep(1.5)
    subprocess.Popen(up_interface_cmd, shell=True, preexec_fn=os.setsid)
    time.sleep(1.5)
    subprocess.Popen(restart_wpa_supplicant, shell=True, preexec_fn=os.setsid)
    time.sleep(3)
    pro = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)


    time.sleep(20)
    os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
    time.sleep(0.5)
