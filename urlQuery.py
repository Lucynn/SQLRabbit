#!/usr/bin/python3

import requests
import urllib.parse

from colorama import Fore

# query
def sendReq(url, params=None, data=None, headers=None, timeout=5, allow_redirects=False):
    try:
        # If parameters are set
        if params:
            # Encode parameter values
            encParams = urllib.parse.urlencode(params, safe='/%+')
            url += '?' + encParams
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        elif data:
            r = requests.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        r.raise_for_status()
        result = r.text
        return r
    
    except requests.exceptions.ConnectionError as e:
        print (Fore.RED + f"[-] A connection error occurred: {e}" + Fore.RESET)
        exit()
        return None
    except requests.exceptions.Timeout as e:
        print (Fore.RED + f"[-] The request time out: {e}" + Fore.RESET)
        exit()
        return None
    except requests.exceptions.HTTPError as e:
        if r is not None and r.status_code == 500:
            return r 
    except requests.exceptions.RequestException as e:
        print (Fore.RED + f"[-] Error executing GET query: {e}" + Fore.RESET)
        exit()
        return None
