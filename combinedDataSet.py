import json
import numpy as np
import pandas as pd
import os
from dlls import dlls

def getZscore(val, labelType):
    # 0 - Trojan, 1 - ransomeware, 2 - worm, 3 - backdoorm, 4 - spyware, 5 - rootkit, 6 - encrypter, 7 - downloaded
    mean = [0.44581, 0.00503229, 0.0086457, 0.0117696, 0.00030322, 0.00614807, 0.0719921, 0.037945]
    std = [0.0891624, 0.0192288, 0.0189522, 0.0333144, 0.00227205, 0.0263416, 0.0622346, 0.0699552]
    return (mean[labelType] - val)/std[labelType] 


malwareData = open("./malwareraw").read()
malwareJson = json.loads(malwareData)

malwareDf = pd.json_normalize(malwareJson)

benginData = open("./benignraw").read()
benginJson = json.loads(benginData)

useAbleTraces = list(os.listdir("malwareTraces/"))

modifiedTraces = []
APIsAndDlls = []

for trace in useAbleTraces:
    modifiedTraces.append(trace[:-4])

useAbleTraces = modifiedTraces

useAbleTracesB = list(os.listdir("benignTraces/"))

modifiedTraces = []
APIsAndDlls = []

for trace in useAbleTracesB:
    modifiedTraces.append(trace[:-4])

useAbleTracesB = modifiedTraces

df = pd.read_csv("./labels/malware.csv")

dynamicMalwareJson = json.loads(open("./dynamic_features_malware.json").read())
dynamicBenginJson  = json.loads(open("./dynamic_features_benign.json").read())

completedData = []

temp = [0,0,0,0,0,0,0,0]

labels = ["trojan", "ransomware", "worm", "backdoor", "spyware", "rootkit", "encrypter", "downloader"]
labels = ["trojan", "worm", "backdoor", "encrypter", "downloader"]
for row in malwareJson:
    datasetRow = df.loc[df["hash"] == row["hash"]]
    label = -1
    zScore = -5

    index = 0
    while index < len(labels):
        try:
            newZScore = getZscore(datasetRow[labels[index]], index).item()
        except ValueError:
            index += 1
            continue
        if newZScore > zScore:
            zScore = newZScore
            label = index
        index += 1
    malwareDf.loc[malwareDf["hash"] == row["hash"], "type"] = label + 1 

combinedData = {"numberOfSections":[], 
                "packed":[], 
                "numberOfMismatchedSectionSizes":[], 
                "numberOfNonStanardHeader": [], 
                "highestSectionEntropy":[], 
                "type": [],
                "shellCodeExecuted": [], 
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
                "dllHyjack": []}


for dll in dlls:
    combinedData[dll] = []


for index, row in malwareDf.iterrows():
    if row["hash"] not in useAbleTraces:
        continue
    # Link the data from dynamic features
    for entry in dynamicMalwareJson:
        if entry["fileHash"] == row["hash"]:
            combinedData['shellCodeExecuted'].append(int(entry["shellCodeExecuted"]))
            combinedData['processInjection'].append(int(entry["processInjection"]))
            combinedData['privilageExcalation'].append(int(entry["privilageExcalation"]))
            combinedData['getClassInfromation'].append(int(entry["getClassInfromation"]))
            combinedData['systemInformation'].append(int(entry["systemInformation"]))
            combinedData['checkGroupPolicy'].append(int(entry["checkGroupPolicy"]))
            combinedData['checkHardware'].append(int(entry["checkHardware"]))
            combinedData['checkCurrentUser'].append(int(entry["checkCurrentUser"]))
            combinedData['startUpPersistence'].append(int(entry["startUpPersistence"]))
            combinedData['graphicsExploit'].append(int(entry["graphicsExploit"]))
            combinedData['internetAccess'].append(int(entry["internetAccess"]))
            combinedData['debugProtection'].append(int(entry["debugProtection"]))
            combinedData['dllHyjack'].append(int(entry["dllHyjack"]))
            for fun in entry["funs"]:
                if fun not in APIsAndDlls:
                    APIsAndDlls.append(fun)
                    if fun not in row["dlls"]:
                        row["dlls"].append(fun)
            for dll in entry["dlls"]:
                if dll not in APIsAndDlls:
                    APIsAndDlls.append(dll)
                    if fun not in row["dlls"]:
                        row["dlls"].append(dll)
            break

    combinedData["numberOfSections"].append(int(row["numberOfSections"]))
    combinedData["packed"].append(row["packed"])
    combinedData["numberOfMismatchedSectionSizes"].append(row["numberOfMismatchedSectionSizes"])
    combinedData["numberOfNonStanardHeader"].append(row["numberOfNonStanardHeader"])
    combinedData["highestSectionEntropy"].append(row["highestSectionEntropy"])
    combinedData["type"].append(row["type"])

    for dll in dlls:
        if dll in row["dlls"]:
            combinedData[dll].append(1)
        else:
            combinedData[dll].append(0)

for row in benginJson:
    notFound = True
    for entry in dynamicBenginJson:
        if entry["fileHash"] == row["hash"]:
            combinedData['shellCodeExecuted'].append(int(entry["shellCodeExecuted"]))
            combinedData['processInjection'].append(int(entry["processInjection"]))
            combinedData['privilageExcalation'].append(int(entry["privilageExcalation"]))
            combinedData['getClassInfromation'].append(int(entry["getClassInfromation"]))
            combinedData['systemInformation'].append(int(entry["systemInformation"]))
            combinedData['checkGroupPolicy'].append(int(entry["checkGroupPolicy"]))
            combinedData['checkHardware'].append(int(entry["checkHardware"]))
            combinedData['checkCurrentUser'].append(int(entry["checkCurrentUser"]))
            combinedData['startUpPersistence'].append(int(entry["startUpPersistence"]))
            combinedData['graphicsExploit'].append(int(entry["graphicsExploit"]))
            combinedData['internetAccess'].append(int(entry["internetAccess"]))
            combinedData['debugProtection'].append(int(entry["debugProtection"]))
            combinedData['dllHyjack'].append(int(entry["dllHyjack"]))
            for fun in entry["funs"]:
                if fun not in APIsAndDlls:
                    APIsAndDlls.append(fun)
                    if fun not in row["dlls"]:
                        row["dlls"].append(fun)
            for dll in entry["dlls"]:
                if dll not in APIsAndDlls:
                    APIsAndDlls.append(dll)
                    if fun not in row["dlls"]:
                        row["dlls"].append(dll)
            notFound = False
            break
    if notFound:
        combinedData['shellCodeExecuted'].append(0)
        combinedData['processInjection'].append(0)
        combinedData['privilageExcalation'].append(0)
        combinedData['getClassInfromation'].append(0)
        combinedData['systemInformation'].append(0)
        combinedData['checkGroupPolicy'].append(0)
        combinedData['checkHardware'].append(0)
        combinedData['checkCurrentUser'].append(0)
        combinedData['startUpPersistence'].append(0)
        combinedData['graphicsExploit'].append(0)
        combinedData['internetAccess'].append(0)
        combinedData['debugProtection'].append(0)
        combinedData['dllHyjack'].append(0)

    combinedData["numberOfSections"].append(int(row["numberOfSections"]))
    combinedData["packed"].append(row["packed"])
    combinedData["numberOfMismatchedSectionSizes"].append(row["numberOfMismatchedSectionSizes"])
    combinedData["numberOfNonStanardHeader"].append(row["numberOfNonStanardHeader"])
    combinedData["highestSectionEntropy"].append(row["highestSectionEntropy"])
    combinedData["type"].append(row["type"])

    for dll in dlls:
        if dll in row["dlls"]:
            combinedData[dll].append(1)
        else:
            combinedData[dll].append(0)



finishedDf = pd.DataFrame(combinedData)
labels = ["bengin", "trojan", "worm", "backdoor", "encrypter", "downloader"]

index = 0
while index < len(labels):
    print(str(index) + ": " + str(finishedDf.loc[finishedDf["type"] == index]["type"].count()))
    index += 1  


finishedDf.to_csv("complete.csv")