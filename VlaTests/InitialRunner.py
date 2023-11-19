from math import pi
import subprocess
import re
import time
import signal
import os
import csv

MININET_FILE_PATH = "/home/VlaTests/hostMacs.csv"



def read_csv_to_dict(file_path):
    data_dict = {}
    with open(file_path, 'rb') as csv_file:
        csv_reader = csv.reader(csv_file)

        # Skip the header row if it exists
        next(csv_reader, None)

        for row in csv_reader:
            key = row[0]
            host_mac = row[1]
            host_ip = row[2]
            data_dict[key] = (host_mac, host_ip)

    return data_dict

def get_rest_of_string_after_prefix(input_string, prefix):
    prefix_position = input_string.find(prefix)
    if prefix_position != -1:
        rest_of_string = input_string[prefix_position + len(prefix):]
        return rest_of_string
    else:
        return None

def extractHostNameAndPid(input_string):
    # Split the string into words
    hostName = None
    processId = None
    words = input_string.split()

    # Check if the string has at least 3 words
    if len(words) >= 4:
        # Print the third word
        processId = words[3]

    # Check if the string has at least 1 word
    if len(words) >= 1:
        # Print the last word
        hostName = get_rest_of_string_after_prefix(words[-1], "mininet:")
    
    return (processId, hostName)

def getNetworkNamespaces():
    try:
        # Run the shell command and capture the output
        result = subprocess.check_output("lsns --type=net", shell=True)

        # Split the output into lines and return as a list
        return result.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print("Error: %s ".format(e))
        return []
    

def run_python_file_in_namespace(namespace_name, hostIp):
    try:
        # Use nsenter to enter the network namespace and run the Python file
        nsenter_command = None
        nsenter_command = ["nsenter", "--net", "--mount", "--ipc", "--pid", "--uts", "--target", namespace_name, "ping", "-c", "2", hostIp]
        process = subprocess.Popen(nsenter_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process

    except subprocess.CalledProcessError as e:
            print("Error: " % e)
            return None


def getMininetHostNamesAndProcessIds():
    output = getNetworkNamespaces()
    output_hosts = []
    for line in output:
        (procoess_id, hostName) = extractHostNameAndPid(line)
        if(procoess_id and hostName):
            output_hosts.append((hostName, procoess_id))
    return output_hosts



def runPingForHostPair(senderHostName, senderHostProcessId, senderIp, receiverHostName, receiverHostMac, receiverHostProcessId, receiverIp):
 
        # Run the second Python file in the second namespace
    ping_sender_process = run_python_file_in_namespace(senderHostProcessId, receiverIp)

    # Wait for the second file to finish and capture its output
   

    time.sleep(1)

    ping_sender_process.terminate()

    # Optionally wait for the first file to terminate gracefully
    ping_sender_process.wait()

   
    ping_listener_process = run_python_file_in_namespace(receiverHostProcessId, senderIp)


    time.sleep(1)

    ping_listener_process.terminate()

    # Optionally wait for the first file to terminate gracefully
    ping_listener_process.wait()
 



def main():
    output_hosts = getMininetHostNamesAndProcessIds()
    hostMacMap = read_csv_to_dict(MININET_FILE_PATH)
    hostCount = len(output_hosts)
    rttDict = {}
    for i in range(0, hostCount):
        for j in range(i+ 1, hostCount):
            senderHostName = output_hosts[i][0]
            receiverHostName = output_hosts[j][0]
            senderPid = output_hosts[i][1]
            receiverPid = output_hosts[j][1]

            receiverMac= hostMacMap[receiverHostName][0]
            receiverIp = hostMacMap[receiverHostName][1]

            senderIp = hostMacMap[senderHostName][1]

            runPingForHostPair(senderHostName, senderPid, senderIp, receiverHostName, receiverMac, receiverPid, receiverIp)

print("initial ping done")


if __name__ == "__main__":
    main()

    