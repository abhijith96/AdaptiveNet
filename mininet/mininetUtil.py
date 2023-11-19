import csv

def get_hosts_info(net):
    hosts_info = []

    # Iterate over hosts and collect information
    for host in net.hosts:
        host_info = {
            'name': host.name,
            'mac': host.MAC(),
            'ip' : host.IP()
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