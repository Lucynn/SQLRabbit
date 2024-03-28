# SQLRabbit
The SQLRabbit is a tool for identifying and extracting data from MySQL databases using Blind Based SQL Injection attack techniques. The tool was made during undergraduate studies as part of the Final Year Project.

# Usage
```diff
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1'
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1' --table users --column password
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1*' --speed=true
python3 SQLRabbit.py --url 'http://127.0.0.1/shop/index.php?page=product&id=1*' --speed=true --table users --column password
```