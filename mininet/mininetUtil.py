import csv



def getIpv6(net, host_name):

    host = net.getNodeByName(host_name)

    # Get MAC and IPv6 addresses using the 'ip' command
    cmd_result = host.cmd('ip -o -6 addr show dev %s' % host.defaultIntf())

    # Extract MAC and IPv6 addresses from the command result
    lines = cmd_result.split('\n')
    mac_address = lines[0].split()[4]
    ipv6_address = lines[1].split()[1].split('/')[0]
    return ipv6_address


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