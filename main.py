#Basic network packet sniffer for Linux
import logging
from datetime import datetime
import subprocess
import sys
import os
from contextlib import redirect_stdout
from bcolors import bcolors


if not os.geteuid()==0:
  print('You should run this script with root privileges.')

#Suppressing all the messages with a lower level of seriousness than error messages, while running Scapy
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('scapy.interactive').setLevel(logging.ERROR)
logging.getLogger('scapy.loading').setLevel(logging.ERROR)

#This should be imported that way according to Scapy doc:
#"In Scapy v2 use from scapy.all import * instead of from Scapy import *"
try:
    from scapy.all import *
except ImportError:
    print('You need to install Python Scapy package to run this script.')
    sys.exit()

interface = input('Enter network interface for sniffing (e.g enp9s0): ')

"""
NOTE: 
promiscous mode - all traffic is passed to the CPU rather than  only the frames that are intended to receive (addressed to the device). 
In this mode every data packet transmitted can be reveived and read by a network adapter. 
"""

#Configuring the promiscious mode
"""
NOTE: If shell is True, the specified command will be executed throught the shell. 
This give access to other shell features such as shell pipes, filename wildcards, environment variable expansion etc.
Invoking the shell is platform-dependent. No execution throught the shell needed here.
"""
try:
    subprocess.call(['ifconfig', interface, 'promisc'], stdout=None, stderr=None, shell=False)
except:
    print('Failed to change the interface mode to promiscous.')
else:
    print(f'Interface {interface} mode changed to promiscous.')

packets_count = input('Enter the number of packets to capture (0 - infinity): ')
sniff_timeout = input('Enter the time for sniffing (seconds): ')
protocol = input('Enter the protocol to filter (e.g arp, icmp) [0 - all protocols]: ')
protocol = protocol.lower()
file_name = input('Enter the name for the file log: ')

print('Running...')

#Sniffing
try:

    if protocol == '0':
        result = sniff(iface=interface, count=int(packets_count), timeout=int(sniff_timeout))
    else:
        result = sniff(iface=interface, filter=protocol ,count=int(packets_count), timeout=int(sniff_timeout))

    try:
        #If it does not exist, it will be created
        with open(file_name, 'a') as file:
            with redirect_stdout(file):
                result.show()
    except:
        print(bcolors.FAIL + 'Could not save to file.' + bcolors.ENDC)
        
except Exception as e:
    print(f'{bcolors.FAIL}{e}{bcolors.ENDC}')

print(f'{bcolors.OKGREEN}Finished. Check the logs file: \'{file_name}\'{bcolors.ENDC}.')