import csv

def get_hosts_info(net):
    hosts_info = []

    # Iterate over hosts and collect information
    for host in net.hosts:
        host_info = {
            'name': host.name,
            'mac': host.MAC()
        }
        hosts_info.append(host_info)

    return hosts_info

def write_to_csv(file_path, data):
    with open(file_path, mode='w', newline='') as csv_file:
        fieldnames = ['name', 'mac']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write the header
        writer.writeheader()

        # Write the data
        for row in data:
            writer.writerow(row)