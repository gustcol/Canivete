# Python Cheatsheet

> And now for something completely different.

## Table of Contents

- [Command-Line Usage](#command-line-usage)
- [Databases](#databases)
- [File Operations](#file-operations)
- [Iteration](#iteration)
- [Network Connections](#network-connections)
- [Type Casting](#type-casting)

## Command-Line Usage

### Argument Parsing
```py
import argparse

parser = argparse.ArgumentParser(description="Something useful.")
parser.add_argument("input", help="Input file", nargs='?')
parser.add_argument("output", help="Output file", nargs='?')
parser.add_argument("--flag", help="An optional flag", action='append')

args = parser.parse_args()

if args.flag is not None:
    print("The flag was provided.")

print(args.input)
print(args.output)
```

### Colors
```py
class colors:
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'

print(f"{colors.bold}{colors.fg.green}Success!")
```

### Execute Shell Commands
```py
import subprocess
cmd = subprocess.Popen(
        ['ls', '-l', '.'],
        cwd='/',
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
)
stdout, stderr = cmd.communicate()
print(stdout)
print(stderr)
```

## Databases

### TinyDB

#### Install
```sh
pip install tinydb
```

#### Use
```py
from tinydb import TinyDB, Query

db = TinyDB('db.json')

# Insert
db.insert({ 'type': 'OSFY', 'count': 700 })
db.insert({ 'type': 'EFY', 'count': 800 })

# Dump
db.all()
# => [{'count': 700, 'type': 'OSFY'}, {'count': 800, 'type': 'EFY'}]

# Search and List
Magazine = Query()
db.search(Magazine.type == 'OSFY')
# => [{'count': 700, 'type': 'OSFY'}]
 
db.search(Magazine.count > 750)
# => [{'count': 800, 'type': 'EFY'}]

# Update
db.update({'count': 1000}, Magazine.type == 'OSFY')
db.all()
# => [{'count': 1000, 'type': 'OSFY'}, {'count': 800, 'type': 'EFY'}]

# Remove
db.remove(Magazine.count < 900)
db.all()
# => [{'count': 800, 'type': 'EFY'}]

# Purge
db.purge()
db.all()
# => []

# In-Memory Use
from tinydb.storages import MemoryStorage
db = TinyDB(storage=MemoryStorage)
```

### SQLite

#### Use

```py
import sqlite3

conn = sqlite3.connect('sqlite.db')

cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS stargazers (id integer PRIMARY KEY, login text, email text)")
conn.commit()

data = ('herrbischoff', 'marcel@example.com')

def sql_insert(data):
    login = data[0]
    cursor.execute(f'SELECT login FROM stargazers WHERE login = "{login}"')
    results = cursor.fetchall()
    if not results:
        cursor.execute('INSERT INTO stargazers (login, email) VALUES (?, ?)', data)
        conn.commit()
    else:
        print(f'User {login} already in database')

def sql_fetch():
    cursor.execute('SELECT * FROM stargazers')
    rows = cursor.fetchall()
    return rows

sql_insert(data)
print(sql_fetch())
```

## File Operations

* `x` creates new file, returns error when it exists.
* `a` appends to file, creates it when it does not exist.
* `w` overwrites file, creates it when it does not exist.

```py
f = open("file.txt", "a")
f.write("More content.")
f.close()
```

## Iteration

### Range
```py
for i in range(10):
    print(i)
```

## Network Connections

### HTTP

#### JSON
```py
import json, urllib.request
req = urllib.request.Request("https://httpbin.org/get")
req.add_header("Accept", "application/json")
try:
    r = urllib.request.urlopen(req)
    data = json.loads(r.read())
    print(json.dumps(data))
except urllib.error.HTTPError as e:
    print(e.code)
    print(e.read())  
```

#### Plain
```py
import urllib.request
req = urllib.request.Request("https://httpbin.org/get")
try:
    r = urllib.request.urlopen(req)
    data = r.read().decode("utf-8")
    print(data)
except urllib.error.HTTPError as e:
    print(e.code)
    print(e.read())  
```

## Type Casting

```py
integer = 42
string = "42"

# To Integer
int(string)

# To String
str(integer)
```
