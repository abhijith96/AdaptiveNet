import csv
from ipaddress import ip_address

import re


LINK_BANDWIDTH = 50
LINK_DELAY = "100us"
LINK_MAX_QUEUE_SIZE = 1000

#LINK_OPTS = dict(bw=10, delay='5ms', loss=10, max_queue_size=1000, use_htb=True)

LINK_OPTS = dict(bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)

def get_word_after_inet6(input_string):
    # Define the pattern using regular expression
    pattern = r'\binet6\s+([\da-fA-F:]+/\d+)\b'

    # Search for the pattern in the input string
    match = re.search(pattern, input_string)

    # Check if the pattern is found
    if match:
        # Extract the word after 'inet'
        word_after_inet = match.group(1)
        return word_after_inet
    else:
        return None

def getIpv6(net, host_name):

    host = net.getNodeByName(host_name)

    # Get MAC and IPv6 addresses using the 'ip' command
    cmd_result = host.cmd('ip -o -6 addr show dev %s' % host.defaultIntf())

    print(cmd_result)

    lines = cmd_result.split('\n')
    mac_address = lines[0].split()[4]
    ipv6_address = get_word_after_inet6(cmd_result)
    ipv6_address_without_mask = ipv6_address.split("/")[0]
    return ipv6_address_without_mask


def get_hosts_info(net):
    hosts_info = []

    # Iterate over hosts and collect information
    for host in net.hosts:
        host_info = {
            'name': host.name,
            'mac': host.MAC(),
            'ip' : getIpv6(net, host.name)
        }
        hosts_info.append(host_info)

    return hosts_info

def write_to_csv(file_path, data):
    with open(file_path, 'wb') as csv_file:  # Use 'wb' for writing in Python 2
        fieldnames = ['name', 'mac', 'ip']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write the header
        writer.writeheader()

        # Write the data
        for row in data:
            writer.writerow(row)