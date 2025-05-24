import os
from gather import get_trace
from extract import *

# Toggle to get the relevant files
target = "malware"
files_to_run = list(os.listdir("files/" + target + "500"))
index = 0
while index < len(files_to_run):
    get_trace(files_to_run[index], target)
    index += 1

files = list(os.listdir(target + "Traces/"))

dynamic_data = []

for file_name in files:
    # Remove file extensionm
    file_hash = file_name[:-4]
    print(file_hash)
    file = open(target + "Traces/" + file_name)
    data = file.read()

    dynamic_row = {"fileHash": file_hash,
                    "shellCodeExecuted": checkShellExecution(data), 
                   "processInjection": checkForInjection(data), 
                   "privilageExcalation": accessTokenInformation(data), 
                   "getClassInfromation": checkClasses(data), 
                   "systemInformation": checkSystemInformation(data), 
                   "checkGroupPolicy": checkGroupPolicy(data), 
                   "checkHardware": checkHardware(data), 
                   "checkCurrentUser": checkCurrentUser(data), 
                   "startUpPersistence": checkStartUp(data), 
                   "graphicsExploit": expoloitGraphicVulnerability(data), 
                   "internetAccess": internetAccess(data), 
                   "debugProtection": debugProtection(data), 
                   "dllHyjack": dllHijack(data),
                   "dlls": getLoadedDlls(data),
                   "funs": getUsedAPI(target + "Traces/"+file_name)}
    
    dynamic_data.append(dynamic_row)

saved_data = open("dynamic_features_" + target + ".json", "w")
saved_data.write(str(dynamic_data))