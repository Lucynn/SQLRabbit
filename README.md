# SQLRabbit
The SQLRabbit is a tool for identifying and extracting data from MySQL databases using Blind Based SQL Injection attack techniques. The tool was made during undergraduate studies as part of the Final Year Project.

# Usage
### Running the tool normally
```
python3 main.py --url 'http://127.0.0.1/shop/index.php?page=product&id=3'
```

### Running with table and column specification
```
python3 main.py --url 'http://127.0.0.1/shop/index.php?page=product&id=3' --table users --column password
```

### Specifying the vulnerable point
```
python3 main.py --url 'http://127.0.0.1/shop/index.php?page=product&id=3*'
```

### Running with faster algorithm (Only works for pages with ?id=1 to ?id=7)
```
python3 main.py --url 'http://127.0.0.1/shop/index.php?page=product&id=3' --speed=true
```

### Running using POST request
```
python3 main.py --url 'http://127.0.0.1/shop/index.php' --speed=true --data="page=product&id=3"
```

### Chose Technique (B = Boolean, T = Time)
```
python3 main.py --url 'http://127.0.0.1/shop/index.php?page=product&id=3' --technique=T
```
