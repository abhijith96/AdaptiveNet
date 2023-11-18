import subprocess
import re


def split_at_six_spaces(input_string):
    # Use regular expression to split at the first occurrence of six non-continuous spaces
    result = re.split(r'(?<!\s)(\s{6})(?!\s)', input_string, maxsplit=1)
    return result

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
for line in output_lines:
    line = split_at_six_spaces(line)
    



# Print the result
print("Output:")
for line in output_lines:
    for word in line:
        print(word)