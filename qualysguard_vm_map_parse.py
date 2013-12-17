# Parse map XML for live but not scannable IPs.

import argparse
import csv
import datetime
from collections import defaultdict
import logging
import os
import qualysapi
from lxml import objectify

#
#  Begin
#
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Parse QualysGuard VM map XML for live but not scannable IPs.')
parser.add_argument('-a', '--asset_group',
                    default = 'Discovered from map',
                    help = 'FUTURE: Asset group to add IPs to.')
parser.add_argument('-c', '--subscribe_from_csv',
                    help = 'FUTURE: Add IPs to subscription.')
parser.add_argument('-e', '--exclude',
                    default = 'exclude.csv',
                    help = 'FUTURE: IPs to exclude from adding to the subscription.')
parser.add_argument('-f', '--file_ip_list',
                    default = '%s_live_not_scannable.csv' % (datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S')),
                    help = 'CSV to output of live, not scannable IPs.')
parser.add_argument('-m', '--map',
                    help = 'Map XML to find live not scannable IPs.')
parser.add_argument('-s', '--subscribe', action = 'store_true',
                    help = 'Automatically add IPs to subscription.')
parser.add_argument('-v', '--debug', action = 'store_true',
                    help = 'Outputs additional information to log.')
parser.add_argument('--config',
                    help = 'Configuration for Qualys connector.')
# Parse arguments.
args = parser.parse_args()# Create log directory.
# Validate input.
if not (args.map or \
        args.subscribe_from_csv):
    parser.print_help()
    exit()
# Create log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
# Set log options.
LOG_FILENAME = '%s/%s-%s.log' % (PATH_LOG,
                                __file__,
                                datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# Make a global logging object.
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
# This handler writes everything to a file.
logger_file = logging.FileHandler(LOG_FILENAME)
logger_file.setFormatter(logging.Formatter("%(asctime)s %(name)-12s %(levelname)s %(funcName)s %(lineno)d %(message)s"))
logger_file.setLevel(logging.INFO)
if c_args.verbose:
    logger_file.setLevel(logging.DEBUG)
logger.addHandler(logger_file)
# This handler prints to screen.
logger_console = logging.StreamHandler(sys.stdout)
logger_console.setLevel(logging.ERROR)
logger.addHandler(logger_console)
#
# Read in XML map.
with open(args.map) as xml_file:
    xml_output = xml_file.read()
tree = objectify.fromstring(xml_output)
# Find live, not scannable IPs.
count = 0
subscribe_me = set()
with open(args.file_ip_list, 'wb') as csvfile:
    csvwriter = csv.writer(csvfile,
                            quoting=csv.QUOTE_ALL)
    # Write header to CSV.
    csvwriter.writerow(['IP', 'Hostname', 'NetBIOS', 'OS'])
    # Add each host.
    for host in tree.HOST_LIST.HOST:
        # Skip to next host if host is already in subscription.
        if host.SCANNABLE == 1:
            continue
        # Skip to next host if host is not alive.
        if host.LIVE == 0:
            continue
        # Grab IP.
        ip = str(host.IP)
        # Grab Hostname.
        hostname = ''
        try:
            hostname = str(host.HOSTNAME)
        except AttributeError, e:
            logging.debug('%s: No hostname.' % (ip, str(e)))
        # Grab NetBIOS.
        netbios = ''
        try:
            netbios = str(host.NETBIOS)
        except AttributeError, e:
            logging.debug('%s: No NetBIOS.' % (ip, str(e)))
        # Grab OS.
        os = ''
        try:
            os = str(host.OS)
        except AttributeError, e:
            logging.debug('%s: No OS.' % (ip, str(e)))
        # Write to CSV.
        csvwriter.writerow([ip, hostname, netbios, os])
        # Increment number of hosts found.
        count += 1
        # Store ip in set.
        subscribe_me.add(ip)
# All data stored. Print out to files.
print 'Number of live, not scannable hosts found: %s' % str(count)
print 'Host details successfully written to %s.' % args.file_ip_list
# Subscribe IPs, if requested.
if not args.subscribe:
    exit()
if c_args.config:
    qgc = qualysapi.connect(c_args.config)
else:
    qgc = qualysapi.connect()
# Combine IPs to comma-delimited string.
formatted_ips_to_subscribe = ','.join(subscribe_me)
# Subscribe IPs.
qgc = qualysapi.connect('asset_ip.php',{'action': 'add', 'host_ips': formatted_ips_to_subscribe})
exit()