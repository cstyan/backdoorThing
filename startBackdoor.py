import argparse
import subprocess

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

subprocess.call("nohup python not_a_backdoor.py -s {0} -d {1}".format(args.sourcePort, args.destPort))