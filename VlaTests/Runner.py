import subprocess

def getNetworkNamespaces():
    try:
        # Run the shell command and capture the output
        result = subprocess.check_output("lsns --type=net", shell=True, universal_newlines=True)

        # Split the output into lines and return as a list
        return result.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return []

# Example: List files in the current directory
command = "ls"
output_lines = getNetworkNamespaces(command)

# Print the result
print("Output:")
for line in output_lines:
    print(line)