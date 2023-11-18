import subprocess
import re


def split_at_six_spaces(input_string):
    # Use regular expression to split at the first occurrence of six non-continuous spaces
    parts = input_string.split()

    # Ensure there are at least six parts
    if len(parts) >= 6:
        # Take the first six parts and join them into six strings
        result = [' '.join(parts[:6])] + parts[6:]
        return result
    else:
        return []
def print_third_and_last_word(input_string):
    # Split the string into words
    words = input_string.split()

    # Check if the string has at least 3 words
    if len(words) >= 3:
        # Print the third word
        print("Third Word:", words[2])

    # Check if the string has at least 1 word
    if len(words) >= 1:
        # Print the last word
        print("Last Word:", words[-1])

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
    print_third_and_last_word(line)
    

    