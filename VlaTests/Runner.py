import subprocess
import re


def get_rest_of_string_after_prefix(input_string, prefix):
    prefix_position = input_string.find(prefix)
    if prefix_position != -1:
        rest_of_string = input_string[prefix_position + len(prefix):]
        return rest_of_string
    else:
        return None

def print_third_and_last_word(input_string):
    # Split the string into words
    hostName = None
    processId = None
    words = input_string.split()

    # Check if the string has at least 3 words
    if len(words) >= 4:
        # Print the third word
        print("Third Word:", words[3])
        processId = words[3]

    # Check if the string has at least 1 word
    if len(words) >= 1:
        # Print the last word
        print("Last Word:", words[-1])
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


output_lines = getNetworkNamespaces()
output_lines_2 = []
for line in output_lines:
    (procoess_id, hostName) = print_third_and_last_word(line)
    if(procoess_id and hostName):
        output_lines_2.append((hostName, procoess_id))

print("len is "+ len(output_lines_2))
for hostName, processId in output_lines_2:
    print("hostName : %s process Id : %s".format(hostName, processId))
    

    