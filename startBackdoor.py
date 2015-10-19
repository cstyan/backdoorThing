import argparse
import subprocess
import os
import shlex

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

cwd = os.getcwd()
args = shlex.split("nohup /usr/bin/python not_a_backdoor.py -s {0} -d {1}".format(args.sourcePort, args.destPort))
subprocess.Popen(args, cwd=cwd)