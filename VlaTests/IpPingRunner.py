from math import pi
import subprocess
import re
import time
import signal
import os
import csv



MININET_FILE_PATH = "/home/VlaTests/hostMacs.csv"
RTT_FILE_PATH = "/home/VlaTests/IP_RTT.csv"

PROCESS_TIME_OUT = 5


pingReceiverProgram = "/home/VlaTests/IpPingReply.py"
pingSenderProgram = "/home/VlaTests/IpPing.py" 

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Subprocess timed out after 2 seconds. Terminating.")


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

def write_dict_to_csv(file_path, data_dict):
    with open(file_path, 'wb') as csv_file:
        # Use csv.writer to write to the CSV file
        csv_writer = csv.writer(csv_file)

        # Write the header row (optional)
        header = ["hostName", "RoundTripTime"]
        csv_writer.writerow(header)

        # Write the data rows
        for key, value in data_dict.items():
            row = []
            row.append(key[0])
            row.append(key[1])
            row.append(value)
            csv_writer.writerow(row)


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
    

def run_python_file_in_namespace(namespace_name, python_file_path, args = []):
    try:
        # Use nsenter to enter the network namespace and run the Python file
        nsenter_command = None
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(PROCESS_TIME_OUT)
        if(len(args) > 0):
            nsenter_command = ["nsenter", "--net", "--mount", "--ipc", "--pid", "--uts", "--target", namespace_name, "python", python_file_path]
            nsenter_command.extend(args)
        else:    
            nsenter_command = ["nsenter", "--net", "--mount", "--ipc", "--pid", "--uts", "--target", namespace_name, "python", python_file_path]
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

def createPingListenerProcesses(hostProcessList, pingListenerPythonCommand):
    subProcessList= []
    for hostName, hostProcessId in hostProcessList:
        subProcess = createPingListenerProcess(hostName, hostProcessId, pingListenerPythonCommand)
        subProcessList.append(subProcess)
    return subProcessList
    

def createPingListenerProcess(hostName, hostProcessId, pingListenerPythonCommand):
    ping_listener_process = run_python_file_in_namespace(hostProcessId, pingListenerPythonCommand)
    return ping_listener_process

def terminatePingListenerProcesses(processList):
    for process in processList:
        process.terminate()
        process.wait()



def runPingForHostPair(senderHostName, senderHostProcessId, senderIp, receiverHostName, receiverHostMac, receiverHostProcessId, receiverIp):
    global pingSenderProgram
    global pingReceiverProgram
    pingPythonCommand = pingSenderProgram
    pingListenerPythonCommand = pingReceiverProgram
       # Run the first Python file in the first namespace
    # ping_listener_process = run_python_file_in_namespace(receiverHostProcessId, pingListenerPythonCommand)

    # # Wait for a moment to ensure the first file is running
    # time.sleep(2)

    # Run the second Python file in the second namespace
    ping_sender_process = None
    try:
        ping_sender_process = run_python_file_in_namespace(senderHostProcessId, pingPythonCommand, args=[receiverHostName,receiverIp])

        # Wait for the second file to finish and capture its output
        output, errors = ping_sender_process.communicate()

        signal.alarm(0)

        # Terminate the first file when the second file ends
        # ping_listener_process.terminate()

        # # Optionally wait for the first file to terminate gracefully
        # ping_listener_process.wait()

        outputString = output.decode('utf-8')

        #print(outputString)

        outputLines = outputString.split("\n")

        for line in outputLines:
            if line.startswith("IpRoundTripTimeis"):
                words = line.split()
                if(len(words) >= 2):
                    round_trip_time = words[1]
                    return (True,round_trip_time)
        return (False, None)
    except TimeoutException as e:
        print("Error : " % e)
        if(ping_sender_process):
            ping_sender_process.terminate()
            ping_sender_process.wait()
        return (False, None)



def main():
    output_hosts = getMininetHostNamesAndProcessIds()
    hostMacMap = read_csv_to_dict(MININET_FILE_PATH)
    hostCount = len(output_hosts)
    rttDict = {}
    pingListenerList = createPingListenerProcesses(output_hosts, pingReceiverProgram)
    time.sleep(2)
    print("listener processes created")
    try:
        for i in range(0, hostCount):
            for j in range(i+ 1, hostCount):
                senderHostName = output_hosts[i][0]
                receiverHostName = output_hosts[j][0]
                senderPid = output_hosts[i][1]
                receiverPid = output_hosts[j][1]

                receiverMac= hostMacMap[receiverHostName][0]
                receiverIp = hostMacMap[receiverHostName][1]

                senderIp = hostMacMap[senderHostName][1]

                print("sender : {} receiver: {}".format(senderHostName, receiverHostName))

                rttFound, rtt = runPingForHostPair(senderHostName, senderPid, senderIp, receiverHostName, receiverMac, receiverPid, receiverIp)
                if(rttFound):
                    print("IP rtt " + rtt)
                    rttDict[(senderHostName, receiverHostName)] = rtt

        write_dict_to_csv(RTT_FILE_PATH, rttDict)
        terminatePingListenerProcesses(pingListenerList)
    except Exception as e:
        print(str(e))
        terminatePingListenerProcesses(pingListenerList)



if __name__ == "__main__":
    main()

    