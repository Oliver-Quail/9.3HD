import json
import pandas as pd


def getZscore(val, labelType):
    # 0 - Trojan, 1 - ransomeware, 2 - worm, 3 - backdoorm, 4 - spyware, 5 - rootkit, 6 - encrypter, 7 - downloaded
    mean = [0.44581, 0.00503229, 0.0086457, 0.0117696, 0.00030322, 0.00614807, 0.0719921, 0.037945]
    std = [0.0891624, 0.0192288, 0.0189522, 0.0333144, 0.00227205, 0.0263416, 0.0622346, 0.0699552]
    return (mean[labelType] - val)/std[labelType] 


malwareData = open("./dynamic_features_malware.json").read()
malwareJson = json.loads(malwareData)

# Get this data to get the class of malware
df = pd.read_csv("./labels/malware.csv")



benignData = open("./dynamic_features_benign.json").read()
benignJson = json.loads(benignData)

dllsAndFuns = []

for row in benignJson:
    for val in row["funs"]:
        if val not in dllsAndFuns:
            dllsAndFuns.append(val)
    for val in row["dlls"]:
        if val not in dllsAndFuns:
            dllsAndFuns.append(val)

for row in malwareJson:
    for val in row["funs"]:
        if val not in dllsAndFuns:
            dllsAndFuns.append(val)
    for val in row["dlls"]:
        if val not in dllsAndFuns:
            dllsAndFuns.append(val)

data = {"shellCodeExecuted": [], 
        "processInjection": [], 
        "privilageExcalation": [], 
        "getClassInfromation": [], 
        "systemInformation": [], 
        "checkGroupPolicy": [], 
        "checkHardware": [], 
        "checkCurrentUser": [], 
        "startUpPersistence": [], 
        "graphicsExploit": [], 
        "internetAccess": [], 
        "debugProtection": [], 
        "dllHyjack": [],
        "type": []}

for val in dllsAndFuns:
    data[val] = []

for row in benignJson:
    data["shellCodeExecuted"].append(int(row["shellCodeExecuted"]))
    data["processInjection"].append(int(row["processInjection"]))
    data["privilageExcalation"].append(int(row["privilageExcalation"]))
    data["getClassInfromation"].append(int(row["getClassInfromation"]))
    data["systemInformation"].append(int(row["systemInformation"]))
    data["checkGroupPolicy"].append(int(row["checkGroupPolicy"]))
    data["checkHardware"].append(int(row["checkHardware"]))
    data["checkCurrentUser"].append(int(row["checkCurrentUser"]))
    data["startUpPersistence"].append(int(row["startUpPersistence"]))
    data["graphicsExploit"].append(int(row["graphicsExploit"]))
    data["internetAccess"].append(int(row["internetAccess"]))
    data["debugProtection"].append(int(row["debugProtection"]))
    data["dllHyjack"].append(int(row["dllHyjack"]))
    data["type"].append(0)

    for val in dllsAndFuns:
        if val in row["funs"] or val in row["dlls"]:
            data[val].append(1)
        else:
            data[val].append(0)

for row in malwareJson:
    data["shellCodeExecuted"].append(int(row["shellCodeExecuted"]))
    data["processInjection"].append(int(row["processInjection"]))
    data["privilageExcalation"].append(int(row["privilageExcalation"]))
    data["getClassInfromation"].append(int(row["getClassInfromation"]))
    data["systemInformation"].append(int(row["systemInformation"]))
    data["checkGroupPolicy"].append(int(row["checkGroupPolicy"]))
    data["checkHardware"].append(int(row["checkHardware"]))
    data["checkCurrentUser"].append(int(row["checkCurrentUser"]))
    data["startUpPersistence"].append(int(row["startUpPersistence"]))
    data["graphicsExploit"].append(int(row["graphicsExploit"]))
    data["internetAccess"].append(int(row["internetAccess"]))
    data["debugProtection"].append(int(row["debugProtection"]))
    data["dllHyjack"].append(int(row["dllHyjack"]))

    labels = ["trojan", "worm", "backdoor", "encrypter", "downloader"]
    datasetRow = df.loc[df["hash"] == row["fileHash"]]
    label = -1
    zScore = -5

    index = 0
    while index < len(labels):
        print("trying" + str(index))
        try:
            newZScore = getZscore(datasetRow[labels[index]], index).item()
        except ValueError:
            index += 1
            continue
        if newZScore > zScore:
            zScore = newZScore
            label = index
        index += 1
    data["type"].append(label + 1)
        
    for val in dllsAndFuns:
        if val in row["funs"] or val in row["dlls"]:
            data[val].append(1)
        else:
            data[val].append(0)


finishedDf = pd.DataFrame(data)

finishedDf.to_csv("dynamic.csv")

print(data["type"])