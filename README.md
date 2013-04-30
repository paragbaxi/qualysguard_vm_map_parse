qualysguard_vm_map_parse
========================

Parse QualysGuard VM maps for live but not scannable IPs.

Input:
QualysGuard map XML.

Output:
Live IPs found in maps but are not in subscription.

usage: map_parse.py [-h] [-a ASSET_GROUP] [-c SUBSCRIBE_FROM_CSV] [-e EXCLUDE]
                    [-f FILE_IP_LIST] [-m MAP] [-s] [-v]

Parse QualysGuard VM map XML for live but not scannable IPs.

optional arguments:
  -h, --help            show this help message and exit
  -a ASSET_GROUP, --asset_group ASSET_GROUP
                        FUTURE: Asset group to add IPs to.
  -c SUBSCRIBE_FROM_CSV, --subscribe_from_csv SUBSCRIBE_FROM_CSV
                        FUTURE: Add IPs to subscription.
  -e EXCLUDE, --exclude EXCLUDE
                        FUTURE: IPs to exclude from adding to the
                        subscription.
  -f FILE_IP_LIST, --file_ip_list FILE_IP_LIST
                        CSV to output of live, not scannable IPs.
  -m MAP, --map MAP     Map XML to find live not scannable IPs.
  -s, --subscribe       FUTURE: Automatically add IPs to subscription.
  -v, --debug           Outputs additional information to log.
