#!/usr/bin/python3

import time

from colorama import Fore
from urlQuery import sendReq
from requests.exceptions import HTTPError

# Identify SQL Injection Vuln
def identifyMySQLTime(url, params, payloads, d, cookies=None):
    # Add some headers. Might change to different one later.
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }
    try:
        originalValues = {k: v for k,v in params.items()}
        for k, v in params.items():
            for payload in payloads:
                params[k] = v + payload
                try:
                    # Send the request with the payload
                    start = time.time()
                    r1 = sendReq(url, data=params, headers=headers, cookies=cookies) if d else sendReq(url, params=params, headers=headers, cookies=cookies)
                    end = time.time()
                    t = end - start
                    if t >= 2:
                        params[k] = originalValues[k]
                        return True, params, k
                    # This could be potentially Boolean-Based
                    #elif r1.status_code == 500:
                    #    print (Fore.GREEN + f"[+] Potential Vulnerability Found with payload: {payload}")
                    #    params[k] = originalValues[k]
                    #    return True, params, k
                except HTTPError as e:
                    if e.response is not None and e.response.status_code != 500:
                        print (Fore.RED + f"[-] HTTP Error: {e}" + Fore.RESET)
            params[k] = originalValues[k]
    
    except HTTPError as e:
        print (Fore.RED + f"[-] HTTP Error: {e}" + Fore.RESET)
    return False, None, None
