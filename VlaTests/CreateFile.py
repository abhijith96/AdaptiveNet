
import os
import sys
import Utils

class CommandLineArgumentExeception(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.custom_message = message

    def __str__(self):
        return "CommandLineArgumentExeception: {}".format(self.custom_message)
def createFile(filePath, file_size_mb):
    
    character_to_repeat = 'H'

    num_repetitions = file_size_mb * 1024 * 1024 // len(character_to_repeat)
    with open(filePath, 'w') as file:
        file.write(character_to_repeat * num_repetitions)

    print("File created successfully.")

def getCommandLineArguments():
    try:
        fileSizeInMB = int(sys.argv[1])
    except Exception():
        raise CommandLineArgumentExeception("Pass Comandline Arguments Properly") 
    

def delete_file(file_path):
    absolute_path = os.path.abspath(file_path)
    if os.path.exists(absolute_path):
        os.remove(absolute_path)
        print("File '{}' deleted.".format(absolute_path))
    else:
        print("File '{}' does not exist.".format(absolute_path))
    

    
if __name__ == "__main__":
    try:
        file_path = Utils.FILE_TRANSFER_SEND_FILE
        file_size_mb = getCommandLineArguments()
        createFile(file_path, file_size_mb=10)
        delete_file(Utils.FILE_TRANSFER_RECEIVE_FILE)
        print("file {} with size {} MB created successfully".format(file_path, str(file_size_mb)))
    except CommandLineArgumentExeception as e:
        print("pass valid commandline arguments , syntax is  FileName targetHostId filePath")