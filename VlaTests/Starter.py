import subprocess
import os

def copy_file_from_container(container_name, source_path, destination_path):
    copy_cmd = f'docker cp {container_name}:{source_path} {destination_path}'
    subprocess.call(copy_cmd, shell=True)

def main():
    container_name = 'mininet'
    container_file_path = '/home/hostMacs.csv'
    host_destination_path = 'hostMacs.csv'
    copy_file_from_container(container_name, container_file_path, host_destination_path)
    print(f"File copied from container {container_name} to {os.path.abspath(host_destination_path)}")

if __name__ == '__main__':
    main()