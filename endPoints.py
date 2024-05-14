#!/usr/bin/python3

import urllib.parse

from colorama import Fore

# endPoints
def getURL(url):
    paramD = {}
    parsedURL = urllib.parse.urlparse(url)
    baseURL = parsedURL.scheme + "://" + parsedURL.netloc + parsedURL.path
    parameters = parsedURL.query
    if parameters:
        for param in parameters.split('&'):
            k, v = param.split('=', 1)
            paramD[k] = v
    else:
        print(Fore.RED + "No parameters provided" + Fore.RESET)
        exit()
    return baseURL, paramD

def getSpecialURL(url):
    paramD = {}
    parsedURL = urllib.parse.urlparse(url)
    baseURL = parsedURL.scheme + "://" + parsedURL.netloc + parsedURL.path
    parameters = parsedURL.query
    if parameters:
        for param in parameters.split('&'):
            k, v = param.split('=', 1)
            if '*' in v:
                specialParam = k
                paramD[k] = v.replace('*', '')
            else:
                paramD[k] = v
    else:
        print(Fore.RED + "No parameters provided" + Fore.RESET)
        exit()
    return baseURL, paramD, specialParam

def getData(url, data):
    paramD = {}
    parsedURL = urllib.parse.urlparse(url)
    if data:
        for d in data.split('&'):
            k, v = d.split('=', 1)
            paramD[k] = v
    else:
        print(Fore.RED + "No data provided" + Fore.RESET)
        exit()
    return url, paramD

def getSpecialData(url, data):
    paramD = {}
    parsedURL = urllib.parse.urlparse(url)
    if data:
        for d in data.split('&'):
            k, v = d.split('=', 1)
            if '*' in v:
                specialParam = k
                paramD[k] = v.replace('*', '')
            else:
                paramD[k] = v
    else:
        print(Fore.RED + "No data provided" + Fore.RESET)
        exit()
    return url, paramD, specialParam