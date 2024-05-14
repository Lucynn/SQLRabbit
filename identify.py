#!/usr/bin/python3

from colorama import Fore
from urlQuery import sendReq
from requests.exceptions import HTTPError

# Identify SQL Injection Vuln
def identifyMySQLBoolean(url, params, payloads, trueFalsePayloads, d):
    # Add some headers. Might change to different one later.
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }
    try:
        r1 = sendReq(url, data=params, headers=headers) if d else sendReq(url, params=params, headers=headers)
        originalValues = {k: v for k,v in params.items()}
        newParamsTrue = params.copy()
        newParamsFalse = params.copy()
        for k, v in params.items():
            newParamsTrue[k] = v + trueFalsePayloads[0]
            newParamsFalse[k] = v + trueFalsePayloads[1]
            rTrue = sendReq(url, data=newParamsTrue, headers=headers) if d else sendReq(url, params=newParamsTrue, headers=headers)
            rFalse = sendReq(url, data=newParamsFalse, headers=headers) if d else sendReq(url, params=newParamsFalse, headers=headers)
            for payload in payloads:
                params[k] = v + payload
                try:
                    # Send the request with the payload
                    r2 = sendReq(url, data=params, headers=headers) if d else sendReq(url, params=params, headers=headers)
                    if r2 is not None and (rTrue.text == r1.text and r1.text != rFalse.text):
                        print (Fore.GREEN + f"[+] Potential Vulnerability Found with payload: {newParamsTrue[k]} and {newParamsFalse[k]}" + Fore.RESET)
                        params[k] = originalValues[k]
                        return True, params, k
                    elif r2 is not None and r2.status_code == 500:
                        print (Fore.GREEN + f"[+] Potential Vulnerability Found with payload: {payload}")
                        params[k] = originalValues[k]
                        return True, params, k
                except HTTPError as e:
                    if e.response is not None and e.response.status_code != 500:
                        print (Fore.RED + f"[-] HTTP Error: {e}" + Fore.RESET)
            params[k] = originalValues[k]
    
    except HTTPError as e:
        print (Fore.RED + f"[-] HTTP Error: {e}" + Fore.RESET)
    return False, None, None
