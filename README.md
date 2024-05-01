# SQLRabbit
The SQLRabbit is a tool for identifying and extracting data from MySQL databases using Blind Based SQL Injection attack techniques. The tool was made during undergraduate studies as part of the Final Year Project.

# Usage
### Running the tool normally
```
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1'
```
### Running the tool normally with table and column specification
```
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1' --table users --column password
```
### Running the tool with a fast algorithm (Need to specify * where the vulnerability is)
```
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1*' --speed=true
```
### Running the tool with a fast algorithm and with table and column specification (Need to specify * where the vulnerability is)
```
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1*' --speed=true --table users --column password
```
