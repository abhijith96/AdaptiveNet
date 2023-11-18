import subprocess
import os

def copy_file_from_container(container_name, source_path, destination_path):
    copy_cmd = f'docker cp {container_name}:{source_path} {destination_path}'
    subprocess.call(copy_cmd, shell=True)

def copy_to_container(container_name, source_path, destination_path):
    # Use subprocess to execute the 'docker cp' command
    copy_cmd = f'docker cp {source_path} {container_name}:{destination_path}'
    subprocess.call(copy_cmd, shell=True)

def run_script_in_docker_container(container_name, script_path):
    command = f"docker exec {container_name} python {script_path}"
    subprocess.run(command, shell=True)

def copyRunnerOutputFile():
    container_name = 'mininet'
    container_file_path = '/home/VlaTests/RTT.csv'
    host_destination_path = 'RTT.csv'
    copy_file_from_container(container_name, container_file_path, host_destination_path)
    print(f"File copied from container {container_name} to {os.path.abspath(host_destination_path)}")



def main():
    container_name = 'mininet'
    container_file_path = '/home/hostMacs.csv'
    host_destination_path = 'hostMacs.csv'
    copy_file_from_container(container_name, container_file_path, host_destination_path)
    print(f"File copied from container {container_name} to {os.path.abspath(host_destination_path)}")

    container_destination_path = "/home/VlaTests/"
    copy_to_container(container_name, ".", container_destination_path)
    print(f"Contents of the current directory copied to {container_name}:{container_destination_path}")

    
    docker_container_name = "mininet"
    script_path_inside_container = "/home/VlaTests/Runner.py"
    run_script_in_docker_container(docker_container_name, script_path_inside_container)

    # Call another function after the script
    copyRunnerOutputFile()

if __name__ == '__main__':
    main()