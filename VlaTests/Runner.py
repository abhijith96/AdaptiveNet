from math import pi
import subprocess
import re
import time
import signal
import os



pingReceiverProgram = "/home/VlaTests/VlaPingListener.py"
pingSenderProgram = "/home/VlaTests/VlaPing.py" 

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
    

def run_python_file_in_namespace(namespace_name, python_file_path):
    try:
        # Use nsenter to enter the network namespace and run the Python file
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



def runPingForHostPair(senderHostName, senderHostProcessId, receiverHostName, receiverHostMac, receiverHostProcessId):
    global pingSenderProgram
    global pingReceiverProgram
    pingPythonCommand = pingSenderProgram + " " + receiverHostMac
    pingListenerPythonCommand = pingReceiverProgram
       # Run the first Python file in the first namespace
    ping_listener_process = run_python_file_in_namespace(receiverHostProcessId, pingListenerPythonCommand)

    # Wait for a moment to ensure the first file is running
    time.sleep(1)

    # Run the second Python file in the second namespace
    ping_sender_process = run_python_file_in_namespace(senderHostProcessId, pingPythonCommand)

    # Wait for the second file to finish and capture its output
    output, errors = ping_sender_process.communicate()

    # Terminate the first file when the second file ends
    ping_listener_process.terminate()

    # Optionally wait for the first file to terminate gracefully
    ping_listener_process.wait()

    outputLines = output.decode('utf-8').split("\n")

    print(outputLines)

    for line in outputLines:
        if line.startswith("RoundTripTimeis"):
            words = line.split()
            if(len(words) >= 2):
                round_trip_time = words[1]
                return (True,round_trip_time)
    return (False, None)
    



def main():
    output_hosts = getMininetHostNamesAndProcessIds()
    for i, j in output_hosts:
        print("host Name " + i + " pid : " + j)

    senderHostName = "h1a"
    receiverHostName = "h1b"
    
    senderPid = "10"
    receiverPid = "12"

    receiverMac= "00:00:00:00:00:1b"

    rttFound, rtt = runPingForHostPair(senderHostName, senderPid, receiverHostName, receiverMac, receiverPid)
    if(rttFound):
        print("rtt " + rtt)

    # Run the first Python file in the first namespace
    # process_1 = run_python_file_in_namespace(namespace_name_1, python_file_path_1)

    # # Wait for a moment to ensure the first file is running
    # time.sleep(1)

    # # Run the second Python file in the second namespace
    # process_2 = run_python_file_in_namespace(namespace_name_2, python_file_path_2)

    # # Wait for the second file to finish and capture its output
    # output, errors = process_2.communicate()

    # # Terminate the first file when the second file ends
    # process_1.terminate()

    # # Optionally wait for the first file to terminate gracefully
    # process_1.wait()

    # outputLines = output.decode('utf-8').split("\n")

    # for line in outputLines:
    #     if line.startswith("RoundTripTimeis"):
    #         words = line.split()
    #         if(len(words) >= 2):
    #             round_trip_time = words[1]

    # print("Output of the second file:")
    # print(output.decode('utf-8'))
    # print("Errors of the second file:")
    # print(errors.decode('utf-8'))
    # print("Both files completed.")

if __name__ == "__main__":
    main()

    