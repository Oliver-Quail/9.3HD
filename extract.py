def check(targets, data):
    for target in targets:
        if target in data:
            return 1
    return 0

def checkShellExecution(data):
    targets = ["ShellExecuteExW"]

    return check(targets, data)

def checkForInjection(data):
    taregts = ["NtOpenProcess", "NtOpenUserProcess", "OpenThread", "NTOpenThread", "CreateRemoteThread", "NtMapViewOfSection"]
    address = ["VirtualAllocEx"]
    write = ["WriteProcessMemory"]
    #We're not checking this
    final = ["ResumeProcess", "ResumeThread", "NtResumeThread"]
    
    if check(taregts, data) and check(address, data) and check(write, data):
        return 1

    return 0

def accessTokenInformation(data):
    targets = ["GetTokenInformation", "AdjustTokenPrivileges", "SetTokenInformation"]

    return check(targets, data)

def checkClasses(data):
    targets = ["HKEY_CLASSES_ROOT"]

    return check(targets, data)

def checkSystemInformation(data):
    targets = ["HKEY_LOCAL_MACHINE"]

    return check(targets, data)

def checkGroupPolicy(data):
    targets = ["HKEY_USERS"]

    return check(targets, data)

def checkHardware(data):
    targets = ["HKEY_CURRENT_CONFIG"]

    return check(targets, data)

def checkCurrentUser(data):
    targets = ["HKEY_CURRENT_USER"]

    return check(targets, data)

def checkStartUp(data):
    targets = ["HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"]
    return check(targets, data)

# Used to check if malware is trying to exploit a certain bug
def expoloitGraphicVulnerability(data):
    targets = ["HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\GRE_Initialize"]
        
    return check(targets, data)

def internetAccess(data):
    targets = ["InternetCrackUrlA", "connect", "gethostbyname"]

    return check(targets, data)

def debugProtection(data):
    targets = ["IsDebuggerPresen", "IsDebuggerPresent"]

    return check(targets, data)

# Check for dll hjacking 
def dllHijack(data):
    targets = ["NtCreateFile", "CreateFile"]
    if check(targets, data):
        for target in targets:
            num_occurences = data.count(target)
            index = 0
            previousIndex = 0
            while index < num_occurences:
                location = data.index(target, previousIndex)
                location_of_path = data.index("filepath", previousIndex) + 7
                res = ""
                count = 0
                while 0:
                    if data[location_of_path + count] == '"':
                        if ".dll" in res and "System32" in res:
                            return 1
                        else:
                            break
                    res += data[location_of_path + count]
                    count += 1

                previousIndex = data.index(target, previousIndex) + 1
                index += 1
    
    return 0


def getLoadedDlls(data):
    foundDlls = []
    targets = ["LdrLoadDll", "LdrGetDllHandle"]

    for target in targets:
        num_occurences = data.count(target)
        index = 0
        previousIndex = 0
        while index < num_occurences:
            location_of_path = data.index("module_name", previousIndex) + 13
            res = ""
            count = 0
            while index < num_occurences:
                if data[location_of_path + count] == '"':
                    if res not in foundDlls:
                        foundDlls.append(res)
                    break
                res += data[location_of_path + count]
                count += 1

            previousIndex = data.index(target, previousIndex) + 1
            index += 1

    return foundDlls


def getUsedAPI(file_path):
    usedFunctions = []
    
    with open(file_path, "r") as file:
        for line in file:
            try:
                split_data = line.split(">")[2]
            except IndexError:
                continue;
            index = 1
            res = ""
            if split_data[index] == "_":
                continue
            while index < len(split_data):
                
                if split_data[index] == "(":
                    if res not in usedFunctions:
                        usedFunctions.append(res)
                    break
                res += split_data[index]
                index += 1
            
    
    return usedFunctions

