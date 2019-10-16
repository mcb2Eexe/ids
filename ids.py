#!/usr/bin/env python3
# - ids.py - #
# - Snort IDS for offline pcap scanning
# - Author: mcb2Eexe
# - Last modified: 16 Oct 19
# - Dependencies: python3, pip3, pip install requests, curl, snort, rules dir, pcap dir, logs dir,
# - ToDo: add alert output, check sig errors, check snort version, check how to use rulepacks best, bash setup script
# - Issues: Rule packs have errors when updated (possibly ubuntu repo snort version), can't delete tar files


import sys
import time
import tarfile
import requests
from os import path
import subprocess as sp


SNORT_PATH = "/etc/snort/"
RULE_PATH = "/etc/snort/community_rules"
SNORT_TAR = "/etc/snort/community_rules/SC.tar.gz"
ET_TAR = "/etc/snort/community_rules/ET.tar.gz"
ET_URL = "https://rules.emergingthreats.net/open/snort-2.9.7.0/emerging.rules.tar.gz"
SNORT_URL = "https://snort.org/downloads/community/community-rules.tar.gz"


# - Clear Terminal - #
def clear():
    sp.call('clear', shell=True)
# --- #


# - Help menu - #
def help(error):
    clear()
    print(error)
    print("\n Usage: $ids.py [pcap] [-h]")
    print("\n     [pcap]  Input pcap file to be scanned")
    print("\n Example: ids file.pcap\n")
# --- #
    

# - Snort Function - #
def snort(pcap):
    sp.call('snort -A full -c {}snort.conf -l {}logs/ -r {}'.format(SNORT_PATH, SNORT_PATH, pcap), shell=True)
# --- #


# - Emerging Threats Function - #
def et(pcap):
    sp.call('snort -A full -c {}snort_et.conf -l {}logs/ -r {}'.format(SNORT_PATH, SNORT_PATH, pcap), shell=True)
# --- #


# - All Rules Function - #
def combined(pcap):
    sp.call('snort -A full -c {}snort_all.conf -l {}logs/ -r {}'.format(SNORT_PATH, SNORT_PATH, pcap), shell=True)
# --- #


# - Update Rules - #
def update(rules, vendor, tar):
    clear()
    print("Searching for {} updates...".format(vendor))
    response = requests.get(rules)
    if response.status_code == 200:
        print("{} update found! Updating...".format(vendor))
        r = requests.get(rules)
        open('{}'.format(tar), 'wb').write(r.content)
        tar = tarfile.open("{}".format(tar), 'r:*')
        tar.extractall('{}'.format(RULE_PATH))
        tar.close()
        print("Update complete!")
        time.sleep(2)
    else:
        print("{} rule update not found!".format(vendor))
# --- #


# - Check Connections - #
def connection_status(url):
    response = requests.get('{}'.format(url))
    return response.status_code
# --- #


# - Start - #
while True:
    if len(sys.argv) != 2:
        help(" Invalid input! Check and try again...")
        exit(0)
    elif not path.exists(sys.argv[1]):
        help(" Pcap not found! Check and try again...")
        exit(0)
    else:
        argv = sys.argv[1]
    clear()
    sp.call('snort -V', shell=True)
    print(" Menu:\n")
    print("   [1] Snort Community Open Rules")
    print("   [2] Emerging Threats Rules")
    print("   [3] All Rules")
    print("   [4] Update Rules")
    arg = input("\n Select an option: ")
    if arg == "1":
        snort(argv)
        break
    if arg == "2":
        et(argv)
        break
    if arg == "3":
        combined(argv)
        break
    if arg == "4":
        update(ET_URL, "ET", ET_TAR)
        update(SNORT_URL, "SC", SNORT_TAR)
        clear()
        continue
    else:
        clear()
        print("\nUnknown input! Expecting integer...\n")
        continue
# - End - #
