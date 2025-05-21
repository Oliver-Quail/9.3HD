import os
import time


def get_trace(file_name):
    os.system(r"VBoxManage startvm 'Lab' --type=headless")
    time.sleep(10)
    print("unsleep")

    os.system("VBoxManage guestcontrol 'Lab' run --exe=cmd.exe --username=SITOliver --password=pass -- cmd.exe /c ' cd C:\\Users\\SITOliver\\Documents && APIMiner.exe --app C:\\Users\\SITOliver\\Documents\\benign500\\{0}' > temp1.txt".format(file_name))

    #Extract the name of the trace for extraction
    os.system(r"VBoxManage guestcontrol 'Lab' run --exe=cmd.exe --username=SITOliver --password=pass -- cmd.exe /c 'dir C:\Users\SITOliver\Documents\data' > temp.txt")


    api_trace_name = open("./temp.txt")

    api_trace_data = api_trace_name.read()
    try:
        start_index =  api_trace_data.index("apiminer_traces")
    except ValueError:
        os.system("VBoxManage controlvm 'Lab' poweroff")
        os.system("VBoxManage snapshot 'Lab' restore 'Malware Ready'")
        time.sleep(2)
        return False

    print(start_index)

    api_trace_file_name = ""

    index = start_index
    t_count = 0 

    while index < len(api_trace_data):
        api_trace_file_name += api_trace_data[index]
        
        if api_trace_data[index] == "t":
            t_count += 1
            if t_count == 3:
                break
        index += 1

    print(api_trace_file_name)

    # Give time for API miner to complete
    time.sleep(10)
    # Extract the logs from the device

    output_file_name = file_name
    output_file_name = output_file_name[:-4] + ".txt"
    print(output_file_name)

    command = "VBoxManage guestcontrol 'Lab' run --exe=cmd.exe --username=SITOliver --password=pass -- cmd.exe /c 'more C:\\Users\\SITOliver\\Documents\\data\\{0}' > {1}".format(api_trace_file_name, output_file_name)

    os.system(command)
    os.system("mv ./" + output_file_name + " ./traces/" + output_file_name)
    os.system("VBoxManage controlvm 'Lab' poweroff")
    os.system("VBoxManage snapshot 'Lab' restore 'Malware Ready'")
    time.sleep(2)
    print("VM reset")

    return True