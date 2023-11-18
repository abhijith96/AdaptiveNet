import subprocess

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

# Print the result
print("Output:")
for line in output_lines:
    print(line)