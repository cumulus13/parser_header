# parser_header

HTTP header and cookie parser library for Python.

[![PyPI version](https://badge.fury.io/py/parser_header.svg)](https://badge.fury.io/py/parser_header)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Complete Header Parsing**: Parse all standard HTTP headers including Content-Type, Accept, Cache-Control, and more
- **Cookie Support**: Full cookie parsing with multiple extraction methods
- **Kwargs Support**: Create and modify headers/cookies using keyword arguments
- **Client Hints**: Parse modern `Sec-CH-UA-*` headers
- **Type Safety**: Full type hints for IDE support
- **Zero Dependencies**: No external dependencies required
- **CLI Tool**: Command-line interface for quick parsing
- **Method Chaining**: Fluent API for easy manipulation
- **Production Ready**: Comprehensive test suite and error handling

## Installation

```bash
pip install parser_header
```

## Table of Contents

- [Quick Start](#quick-start)
- [HeaderParser](#headerparser)
  - [Parsing Headers](#parsing-headers)
  - [Setting Headers](#setting-headers)
  - [Accessing Headers](#accessing-headers)
  - [Special Header Parsing](#special-header-parsing)
- [CookieParser](#cookieparser)
  - [Parsing Cookies](#parsing-cookies)
  - [Setting Cookies](#setting-cookies)
  - [Output Methods](#output-methods)
- [CLI Usage](#cli-usage)
- [API Reference](#api-reference)

---

## Quick Start

```python
from parser_header import HeaderParser, CookieParser

# Parse raw headers
raw = """content-type: application/json
content-length: 1024
cookie: session=abc123; user=john
"""
parser = HeaderParser(raw)
print(parser.content_type)  # 'application/json'
print(parser.get_cookies_as_dict())  # {'session': 'abc123', 'user': 'john'}

# Or create from kwargs
parser = HeaderParser(content_type='application/json', user_agent='MyApp/1.0')
print(parser.to_raw())
# Output:
# content-type: application/json
# user-agent: MyApp/1.0
```

---

## HeaderParser

### Parsing Headers

#### From Raw String/Bytes

```python
from parser_header import HeaderParser

raw_headers = """content-length: 1171
content-type: application/json
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/144.0.0.0
accept: */*
accept-language: en-US,en;q=0.9,es;q=0.8
accept-encoding: gzip, deflate, br, zstd
cache-control: max-age=3600, public
dnt: 1
sec-ch-ua: "Chrome";v="144", "Not A Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
origin: https://example.com
referer: https://example.com/page
cookie: session=abc123
cookie: uid=user456
priority: u=1, i
"""

parser = HeaderParser(raw_headers)

print(f"Total headers: {len(parser)}")
# Output: Total headers: 15

print(f"Header names: {parser.keys()}")
# Output: Header names: ['content-length', 'content-type', 'user-agent', 'accept', ...]
```

#### From Kwargs (Underscore → Hyphen Auto-Conversion)

```python
from parser_header import HeaderParser

# Underscores in key names are automatically converted to hyphens
parser = HeaderParser(
    content_type='application/json',
    content_length='1024',
    user_agent='MyApp/1.0',
    x_request_id='req-12345',
    x_custom_header='custom-value',
    accept='*/*'
)

print(parser.to_raw())
# Output:
# content-type: application/json
# content-length: 1024
# user-agent: MyApp/1.0
# x-request-id: req-12345
# x-custom-header: custom-value
# accept: */*

print('x-request-id' in parser)  # True
print('x_request_id' in parser)  # True (also works)
```

#### Mixed: Raw Data + Kwargs

```python
from parser_header import HeaderParser

raw = "content-type: text/html\naccept: */*"

parser = HeaderParser(raw, user_agent='Mozilla/5.0', x_token='abc123')

print(parser.to_dict())
# Output:
# {
#     'content-type': HeaderValue(value='text/html', params={}),
#     'accept': [{'type': '*/*', 'q': 1.0}],
#     'user-agent': 'Mozilla/5.0',
#     'x-token': 'abc123'
# }
```

#### From Dict or Factory Methods

```python
from parser_header import HeaderParser

# From dictionary
headers_dict = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token123',
    'X-Request-ID': 'req-456'
}
parser = HeaderParser.from_dict(headers_dict)

print(parser.content_type)  # 'application/json'
print(parser.get('authorization'))  # 'Bearer token123'

# From kwargs factory
parser = HeaderParser.from_kwargs(
    content_type='text/xml',
    cache_control='no-cache'
)
print(parser.to_raw())
# Output:
# content-type: text/xml
# cache-control: no-cache
```

#### From Requests Response

```python
from parser_header import HeaderParser
import requests

response = requests.get('https://httpbin.org/get')
parser = HeaderParser.from_requests_response(response)

print(parser.content_type)  # 'application/json'
print(parser.get('date'))   # 'Sat, 22 Nov 2025 10:30:00 GMT'
```

---

### Setting Headers

#### Using set() Method

```python
from parser_header import HeaderParser

parser = HeaderParser()

# Positional arguments
parser.set('Content-Type', 'application/json')

# Kwargs only
parser.set(user_agent='Mozilla/5.0', accept='*/*')

# Mixed positional + kwargs
parser.set('Authorization', 'Bearer token', x_request_id='12345')

print(parser.to_raw())
# Output:
# content-type: application/json
# user-agent: Mozilla/5.0
# accept: */*
# authorization: Bearer token
# x-request-id: 12345
```

#### Using set_raw() (No Value Parsing)

```python
from parser_header import HeaderParser

parser = HeaderParser()

# set() parses the value
parser.set('cache-control', 'max-age=3600, public')
print(parser.get('cache-control'))
# Output: {'max-age': 3600, 'public': True}

# set_raw() keeps value as-is
parser.set_raw('x-raw-header', 'max-age=3600, public')
print(parser.get('x-raw-header'))
# Output: 'max-age=3600, public'
```

#### Using Bracket Notation

```python
from parser_header import HeaderParser

parser = HeaderParser()

parser['Content-Type'] = 'application/json'
parser['X-Custom'] = 'value'

print(parser['content-type'])  # application/json (case-insensitive)

del parser['X-Custom']
print('x-custom' in parser)  # False
```

#### Using update() Method

```python
from parser_header import HeaderParser

parser = HeaderParser(content_type='text/html')

# Update from dict
parser.update({'Accept': '*/*', 'Accept-Language': 'en-US'})

# Update from kwargs
parser.update(user_agent='TestAgent', x_token='abc')

# Mixed
parser.update({'Cache-Control': 'no-cache'}, dnt='1')

print(parser.to_raw())
# Output:
# content-type: text/html
# accept: */*
# accept-language: en-US
# user-agent: TestAgent
# x-token: abc
# cache-control: no-cache
# dnt: 1
```

#### Method Chaining

```python
from parser_header import HeaderParser

parser = (
    HeaderParser()
    .set(content_type='application/json')
    .set(accept='*/*')
    .set(user_agent='MyApp/1.0')
    .set_cookie(session='abc123', user='john')
)

print(parser.to_raw())
# Output:
# content-type: application/json
# accept: */*
# user-agent: MyApp/1.0

print(parser.get_cookies_as_header())
# Output: session=abc123; user=john
```

#### Removing and Clearing

```python
from parser_header import HeaderParser

parser = HeaderParser(
    content_type='application/json',
    accept='*/*',
    user_agent='Test',
    x_custom='value'
)

# Remove specific headers
parser.remove('x-custom', 'accept')
print(parser.keys())
# Output: ['content-type', 'user-agent']

# Clear all
parser.clear()
print(len(parser))  # 0
```

---

### Accessing Headers

#### Basic Access

```python
from parser_header import HeaderParser

raw = """content-type: application/json; charset=utf-8
content-length: 1024
user-agent: Mozilla/5.0
"""

parser = HeaderParser(raw)

# get() method (case-insensitive, with default)
print(parser.get('Content-Type'))      # HeaderValue(value='application/json', params={'charset': 'utf-8'})
print(parser.get('X-Missing', 'N/A'))  # 'N/A'

# Bracket notation
print(parser['user-agent'])  # 'Mozilla/5.0'

# Property shortcuts
print(parser.content_type)    # 'application/json'
print(parser.content_length)  # 1024 (as int)
print(parser.user_agent)      # 'Mozilla/5.0'
print(parser.origin)          # None
print(parser.referer)         # None

# Check existence
print('content-type' in parser)  # True
print('x-missing' in parser)     # False
```

#### Iteration

```python
from parser_header import HeaderParser

parser = HeaderParser(content_type='application/json', accept='*/*', dnt='1')

# Iterate keys
for name in parser:
    print(f"{name}: {parser[name]}")
# Output:
# content-type: application/json
# accept: [{'type': '*/*', 'q': 1.0}]
# dnt: True

# Get all keys, values, items
print(parser.keys())    # ['content-type', 'accept', 'dnt']
print(parser.values())  # [HeaderValue(...), [{'type': '*/*', 'q': 1.0}], True]
print(parser.items())   # [('content-type', HeaderValue(...)), ...]
```

#### Export/Conversion

```python
from parser_header import HeaderParser

parser = HeaderParser(
    content_type='application/json',
    accept='*/*',
    dnt='1'
)

# To dictionary
print(parser.to_dict())
# Output:
# {
#     'content-type': HeaderValue(value='application/json', params={}),
#     'accept': [{'type': '*/*', 'q': 1.0}],
#     'dnt': True
# }

# To dictionary with stringified values
print(parser.to_dict(stringify=True))
# Output:
# {
#     'content-type': 'application/json',
#     'accept': "[{'type': '*/*', 'q': 1.0}]",
#     'dnt': 'True'
# }

# To raw format
print(parser.to_raw())
# Output:
# content-type: application/json
# accept: [{'type': '*/*', 'q': 1.0}]
# dnt: 1

# To requests-compatible dict (all string values)
headers = parser.to_requests_headers()
print(headers)
# Output: {'content-type': 'application/json', 'accept': "*/*", 'dnt': '1'}

# Use with requests library
import requests
response = requests.get('https://example.com', headers=headers)
```

---

### Special Header Parsing

#### Content-Type with Parameters

```python
from parser_header import HeaderParser

parser = HeaderParser()
parser.set('content-type', 'text/html; charset=utf-8; boundary=something')

ct = parser.get('content-type')
print(f"Type: {ct}")           # HeaderValue(value='text/html', params={'charset': 'utf-8', 'boundary': 'something'})
print(f"Value: {ct.value}")    # 'text/html'
print(f"Charset: {ct.params['charset']}")    # 'utf-8'
print(f"Boundary: {ct.params['boundary']}")  # 'something'

# Property returns just the value
print(parser.content_type)  # 'text/html'
```

#### Accept-Language with Quality Values

```python
from parser_header import HeaderParser

parser = HeaderParser()
parser.set('accept-language', 'en-US,en;q=0.9,es;q=0.8,fr;q=0.7')

langs = parser.get('accept-language')
print(langs)
# Output (sorted by quality, descending):
# [
#     {'lang': 'en-US', 'q': 1.0},
#     {'lang': 'en', 'q': 0.9},
#     {'lang': 'es', 'q': 0.8},
#     {'lang': 'fr', 'q': 0.7}
# ]

# Get preferred language
print(f"Preferred: {langs[0]['lang']}")  # 'en-US'
```

#### Accept Header

```python
from parser_header import HeaderParser

parser = HeaderParser()
parser.set('accept', 'text/html,application/json;q=0.9,*/*;q=0.8')

accept = parser.get('accept')
print(accept)
# Output:
# [
#     {'type': 'text/html', 'q': 1.0},
#     {'type': 'application/json', 'q': 0.9},
#     {'type': '*/*', 'q': 0.8}
# ]
```

#### Cache-Control

```python
from parser_header import HeaderParser

parser = HeaderParser()
parser.set('cache-control', 'max-age=3600, public, no-transform')

cache = parser.get('cache-control')
print(cache)
# Output:
# {
#     'max-age': 3600,        # Parsed as int
#     'public': True,
#     'no-transform': True
# }

print(f"Max age: {cache['max-age']} seconds")  # 3600
```

#### Boolean Headers (DNT, Sec-GPC)

```python
from parser_header import HeaderParser

parser = HeaderParser()
parser.set('dnt', '1')
parser.set('sec-gpc', '1')
parser.set('upgrade-insecure-requests', '1')

print(parser.get('dnt'))      # True (parsed as boolean)
print(parser.get('sec-gpc'))  # True
print(parser.get('upgrade-insecure-requests'))  # True
```

#### Client Hints (Sec-CH-UA-*)

```python
from parser_header import HeaderParser

raw = """sec-ch-ua: "Chrome";v="144", "Not A Brand";v="8", "Chromium";v="144"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-ch-ua-arch: "x86"
sec-ch-ua-bitness: "64"
sec-ch-ua-full-version: "144.0.7524.3"
sec-ch-ua-platform-version: "15.0.0"
"""

parser = HeaderParser(raw)

# sec-ch-ua parsed as list of brands
ua = parser.get('sec-ch-ua')
print(ua)
# Output:
# [
#     {'brand': 'Chrome', 'version': '144'},
#     {'brand': 'Not A Brand', 'version': '8'},
#     {'brand': 'Chromium', 'version': '144'}
# ]

# sec-ch-ua-mobile parsed as boolean
print(parser.get('sec-ch-ua-mobile'))  # False

# Other values have quotes stripped
print(parser.get('sec-ch-ua-platform'))  # 'Windows'
print(parser.get('sec-ch-ua-arch'))      # 'x86'

# Get all client hints
hints = parser.get_client_hints()
print(hints)
# Output:
# {
#     'sec-ch-ua': [{'brand': 'Chrome', 'version': '144'}, ...],
#     'sec-ch-ua-mobile': False,
#     'sec-ch-ua-platform': 'Windows',
#     'sec-ch-ua-arch': 'x86',
#     'sec-ch-ua-bitness': '64',
#     'sec-ch-ua-full-version': '144.0.7524.3',
#     'sec-ch-ua-platform-version': '15.0.0'
# }
```

#### Priority Header

```python
from parser_header import HeaderParser

parser = HeaderParser()
parser.set('priority', 'u=1, i')

priority = parser.get('priority')
print(priority)
# Output: {'u': '1', 'i': True}
```

#### Sec-Fetch Metadata

```python
from parser_header import HeaderParser

raw = """sec-fetch-site: same-origin
sec-fetch-mode: cors
sec-fetch-dest: empty
"""

parser = HeaderParser(raw)

metadata = parser.get_sec_fetch_metadata()
print(metadata)
# Output:
# {
#     'site': 'same-origin',
#     'mode': 'cors',
#     'dest': 'empty',
#     'user': ''
# }
```

#### CORS and AJAX Detection

```python
from parser_header import HeaderParser

parser = HeaderParser(
    origin='https://example.com',
    x_requested_with='XMLHttpRequest'
)

print(parser.is_cors())  # True
print(parser.is_ajax())  # True

parser2 = HeaderParser(user_agent='Mozilla/5.0')
print(parser2.is_cors())  # False
print(parser2.is_ajax())  # False
```

---

## CookieParser

### Parsing Cookies

#### From Raw String (Multiple Lines)

```python
from parser_header import CookieParser

raw_cookies = """cookie: nonce=Ofymgy29
cookie: sz=1490
cookie: pr=1.25
cookie: uid=2ca13899eb7a
cookie: sid=1:KUo/b68Cp0mhPre4OYgcLF
cookie: xsrf=a9a6c92dc170
"""

cookies = CookieParser(raw_cookies)

print(f"Total cookies: {len(cookies)}")
# Output: Total cookies: 6

print(cookies.to_dict())
# Output:
# {
#     'nonce': 'Ofymgy29',
#     'sz': '1490',
#     'pr': '1.25',
#     'uid': '2ca13899eb7a',
#     'sid': '1:KUo/b68Cp0mhPre4OYgcLF',
#     'xsrf': 'a9a6c92dc170'
# }
```

#### From Single Line (Semicolon-Separated)

```python
from parser_header import CookieParser

single_line = "cookie: session=abc123; user=john; token=xyz789"

cookies = CookieParser(single_line)

print(cookies.to_dict())
# Output: {'session': 'abc123', 'user': 'john', 'token': 'xyz789'}
```

#### From Kwargs

```python
from parser_header import CookieParser

# Underscores converted to hyphens
cookies = CookieParser(
    session='abc123',
    user_id='12345',
    auth_token='xyz789',
    refresh_token='refresh123'
)

print(cookies.to_dict())
# Output:
# {
#     'session': 'abc123',
#     'user-id': '12345',
#     'auth-token': 'xyz789',
#     'refresh-token': 'refresh123'
# }

print(cookies.to_cookie_header())
# Output: session=abc123; user-id=12345; auth-token=xyz789; refresh-token=refresh123
```

#### Mixed: Raw + Kwargs

```python
from parser_header import CookieParser

raw = "cookie: existing=value"

cookies = CookieParser(raw, new_cookie='new_value', another='test')

print(cookies.to_dict())
# Output:
# {
#     'existing': 'value',
#     'new-cookie': 'new_value',
#     'another': 'test'
# }
```

#### From Dict or Factory Methods

```python
from parser_header import CookieParser

# From dictionary
cookies = CookieParser.from_dict({
    'session': 'abc',
    'user': 'john',
    'token': 'xyz'
})
print(cookies.to_cookie_header())
# Output: session=abc; user=john; token=xyz

# From kwargs factory
cookies = CookieParser.from_kwargs(
    session='test123',
    remember_me='true'
)
print(cookies.to_cookie_header())
# Output: session=test123; remember-me=true
```

---

### Setting Cookies

#### Using set() Method

```python
from parser_header import CookieParser

cookies = CookieParser()

# Positional arguments
cookies.set('session', 'abc123')

# Kwargs only
cookies.set(user='john', token='xyz')

# Mixed
cookies.set('admin', 'true', refresh_token='refresh123')

print(cookies.to_dict())
# Output:
# {
#     'session': 'abc123',
#     'user': 'john',
#     'token': 'xyz',
#     'admin': 'true',
#     'refresh-token': 'refresh123'
# }
```

#### Using Bracket Notation

```python
from parser_header import CookieParser

cookies = CookieParser()

cookies['session'] = 'abc123'
cookies['user'] = 'john'

print(cookies['session'])  # 'abc123'

del cookies['user']
print('user' in cookies)  # False
```

#### Using update() Method

```python
from parser_header import CookieParser

cookies = CookieParser(existing='value')

# From dict
cookies.update({'new1': 'val1', 'new2': 'val2'})

# From kwargs
cookies.update(new3='val3', new4='val4')

# Mixed
cookies.update({'from_dict': 'yes'}, from_kwargs='also_yes')

print(cookies.to_dict())
# Output:
# {
#     'existing': 'value',
#     'new1': 'val1',
#     'new2': 'val2',
#     'new3': 'val3',
#     'new4': 'val4',
#     'from-dict': 'yes',
#     'from-kwargs': 'also_yes'
# }
```

#### Method Chaining

```python
from parser_header import CookieParser

cookies = (
    CookieParser()
    .set('session', 'abc')
    .set(user='john')
    .set(token='xyz', admin='false')
    .remove('admin')
)

print(cookies.to_cookie_header())
# Output: session=abc; user=john; token=xyz
```

#### Removing and Clearing

```python
from parser_header import CookieParser

cookies = CookieParser(a='1', b='2', c='3', d='4')

# Remove specific cookies
cookies.remove('a', 'b')
print(cookies.keys())  # ['c', 'd']

# Clear all
cookies.clear()
print(len(cookies))  # 0
```

---

### Output Methods

#### to_cookie_header() - Cookie Header Format

```python
from parser_header import CookieParser

cookies = CookieParser(session='abc', user='john', token='xyz')

# Basic usage
header = cookies.to_cookie_header()
print(header)
# Output: session=abc; user=john; token=xyz

# With additional cookies via kwargs
header = cookies.to_cookie_header(extra='value', another='test')
print(header)
# Output: session=abc; user=john; token=xyz; extra=value; another=test

# Use in HTTP request
import urllib.request
req = urllib.request.Request('https://example.com')
req.add_header('Cookie', cookies.to_cookie_header())
```

#### to_dict() - Dictionary Format

```python
from parser_header import CookieParser

cookies = CookieParser(session='abc', user='john')

# Basic usage
d = cookies.to_dict()
print(d)
# Output: {'session': 'abc', 'user': 'john'}

# With additional cookies
d = cookies.to_dict(extra='value')
print(d)
# Output: {'session': 'abc', 'user': 'john', 'extra': 'value'}

# Use with requests library
import requests
response = requests.get('https://example.com', cookies=cookies.to_dict())
```

#### Accessing Individual Cookies

```python
from parser_header import CookieParser

cookies = CookieParser(session='abc', user_id='123', auth_token='xyz')

# get() with default
print(cookies.get('session'))           # 'abc'
print(cookies.get('missing', 'N/A'))    # 'N/A'

# Underscore/hyphen interchangeable
print(cookies.get('user-id'))     # '123'
print(cookies.get('user_id'))     # '123'
print(cookies.get('auth-token'))  # 'xyz'
print(cookies.get('auth_token'))  # 'xyz'

# Bracket notation
print(cookies['session'])  # 'abc'

# Iteration
for name in cookies:
    print(f"{name}={cookies[name]}")
# Output:
# session=abc
# user-id=123
# auth-token=xyz

# Keys, values, items
print(cookies.keys())    # ['session', 'user-id', 'auth-token']
print(cookies.values())  # ['abc', '123', 'xyz']
print(cookies.items())   # [('session', 'abc'), ('user-id', '123'), ('auth-token', 'xyz')]
```

---

### Cookies via HeaderParser

```python
from parser_header import HeaderParser

raw = """content-type: application/json
cookie: session=abc123
cookie: user=john
cookie: token=xyz789
"""

parser = HeaderParser(raw)

# Access CookieParser instance
print(parser.cookies.to_dict())
# Output: {'session': 'abc123', 'user': 'john', 'token': 'xyz789'}

# Shortcut methods
print(parser.get_cookie('session'))      # 'abc123'
print(parser.get_cookie('missing', ''))  # ''
print(parser.get_cookies_as_header())    # 'session=abc123; user=john; token=xyz789'
print(parser.get_cookies_as_dict())      # {'session': 'abc123', 'user': 'john', 'token': 'xyz789'}

# Set cookies
parser.set_cookie('new_session', 'newsess123')
parser.set_cookie(admin='true', refresh='refresh123')

print(parser.get_cookies_as_header())
# Output: session=abc123; user=john; token=xyz789; new_session=newsess123; admin=true; refresh=refresh123
```

---

## CLI Usage

### Parse Headers

```bash
# From file
$ parser-header parse -f headers.txt
{
  "content-type": {"value": "application/json", "params": {}},
  "content-length": 1024,
  "user-agent": "Mozilla/5.0"
}

# Get specific header
$ parser-header parse -f headers.txt --header user-agent
"Mozilla/5.0"

# From stdin
$ cat headers.txt | parser-header parse --stdin
{
  "content-type": {"value": "application/json", "params": {}},
  ...
}

# Raw output format
$ parser-header parse -f headers.txt --format raw
content-type: application/json
content-length: 1024
user-agent: Mozilla/5.0
```

### Parse Cookies

```bash
# From full headers file
$ parser-header cookies -f headers.txt --full-headers
{
  "session": "abc123",
  "user": "john",
  "token": "xyz789"
}

# As Cookie header format
$ parser-header cookies -f headers.txt --full-headers --as-header
session=abc123; user=john; token=xyz789

# Get specific cookie
$ parser-header cookies -f headers.txt --full-headers -c session
abc123

# From cookie-only file
$ parser-header cookies -f cookies.txt
{
  "session": "abc123",
  "user": "john"
}
```

### Show Header Info

```bash
$ parser-header info -f headers.txt
{
  "total_headers": 15,
  "total_cookies": 3,
  "content_type": "application/json",
  "content_length": 1024,
  "user_agent": "Mozilla/5.0",
  "origin": "https://example.com",
  "is_cors": true,
  "sec_fetch": {
    "site": "same-origin",
    "mode": "cors",
    "dest": "empty",
    "user": ""
  },
  "client_hints": {
    "sec-ch-ua": [{"brand": "Chrome", "version": "144"}],
    "sec-ch-ua-mobile": false,
    "sec-ch-ua-platform": "Windows"
  }
}
```

---

## API Reference

### HeaderParser

| Method/Property | Description | Example |
|----------------|-------------|---------|
| `HeaderParser(data?, **kwargs)` | Constructor | `HeaderParser(raw)` or `HeaderParser(content_type='json')` |
| `parse(data?, **kwargs)` | Parse headers | `parser.parse(raw, accept='*/*')` |
| `set(name?, value?, **kwargs)` | Set header(s) | `parser.set('Content-Type', 'json')` or `parser.set(accept='*/*')` |
| `set_raw(name, value, **kwargs)` | Set without parsing | `parser.set_raw('X-Raw', 'value')` |
| `get(name, default?)` | Get header (case-insensitive) | `parser.get('content-type')` |
| `remove(*names)` | Remove headers | `parser.remove('x-custom', 'accept')` |
| `clear()` | Clear all headers | `parser.clear()` |
| `update(dict?, **kwargs)` | Update from dict/kwargs | `parser.update({'Accept': '*/*'}, dnt='1')` |
| `to_dict(stringify?)` | Export as dictionary | `parser.to_dict()` or `parser.to_dict(stringify=True)` |
| `to_raw()` | Export as raw format | `parser.to_raw()` |
| `to_requests_headers()` | Export for requests lib | `requests.get(url, headers=parser.to_requests_headers())` |
| `keys()` | Get header names | `parser.keys()` |
| `values()` | Get header values | `parser.values()` |
| `items()` | Get name-value pairs | `parser.items()` |
| `cookies` | Access CookieParser | `parser.cookies.to_dict()` |
| `get_cookie(name, default?)` | Get specific cookie | `parser.get_cookie('session')` |
| `set_cookie(name?, value?, **kwargs)` | Set cookie(s) | `parser.set_cookie(session='abc')` |
| `get_cookies_as_header()` | Cookies as header string | `parser.get_cookies_as_header()` |
| `get_cookies_as_dict()` | Cookies as dictionary | `parser.get_cookies_as_dict()` |
| `content_type` | Content-Type value | `parser.content_type` → `'application/json'` |
| `content_length` | Content-Length as int | `parser.content_length` → `1024` |
| `user_agent` | User-Agent value | `parser.user_agent` |
| `origin` | Origin value | `parser.origin` |
| `referer` | Referer value | `parser.referer` |
| `is_cors()` | Check if CORS request | `parser.is_cors()` → `True/False` |
| `is_ajax()` | Check if AJAX request | `parser.is_ajax()` → `True/False` |
| `get_client_hints()` | Get Sec-CH-* headers | `parser.get_client_hints()` |
| `get_sec_fetch_metadata()` | Get Sec-Fetch-* headers | `parser.get_sec_fetch_metadata()` |
| `from_dict(dict)` | Create from dictionary | `HeaderParser.from_dict({'Content-Type': 'json'})` |
| `from_kwargs(**kwargs)` | Create from kwargs | `HeaderParser.from_kwargs(content_type='json')` |
| `from_requests_response(resp)` | Create from Response | `HeaderParser.from_requests_response(response)` |

### CookieParser

| Method | Description | Example |
|--------|-------------|---------|
| `CookieParser(data?, **kwargs)` | Constructor | `CookieParser(raw)` or `CookieParser(session='abc')` |
| `parse(data?, **kwargs)` | Parse cookies | `cookies.parse(raw, extra='value')` |
| `set(name?, value?, **kwargs)` | Set cookie(s) | `cookies.set('session', 'abc')` or `cookies.set(user='john')` |
| `get(name, default?)` | Get specific cookie | `cookies.get('session')` |
| `remove(*names)` | Remove cookies | `cookies.remove('session', 'token')` |
| `clear()` | Clear all cookies | `cookies.clear()` |
| `update(dict?, **kwargs)` | Update from dict/kwargs | `cookies.update({'a': '1'}, b='2')` |
| `to_cookie_header(data?, **kwargs)` | Export as header string | `cookies.to_cookie_header()` → `'a=1; b=2'` |
| `to_dict(data?, **kwargs)` | Export as dictionary | `cookies.to_dict()` → `{'a': '1', 'b': '2'}` |
| `keys()` | Get cookie names | `cookies.keys()` |
| `values()` | Get cookie values | `cookies.values()` |
| `items()` | Get name-value pairs | `cookies.items()` |
| `from_dict(dict)` | Create from dictionary | `CookieParser.from_dict({'session': 'abc'})` |
| `from_kwargs(**kwargs)` | Create from kwargs | `CookieParser.from_kwargs(session='abc')` |

### HeaderValue

| Property/Method | Description | Example |
|-----------------|-------------|---------|
| `value` | Main header value | `hv.value` → `'text/html'` |
| `params` | Parameter dictionary | `hv.params` → `{'charset': 'utf-8'}` |
| `str(hv)` | String representation | `str(hv)` → `'text/html; charset=utf-8'` |

---

## Supported Headers

### Standard Headers
- `Content-Type`, `Content-Length`, `Content-Disposition`, `Content-Encoding`
- `Accept`, `Accept-Language`, `Accept-Encoding`, `Accept-Charset`
- `Cache-Control`, `Pragma`, `Expires`
- `Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`
- `Cookie`, `Set-Cookie`
- `User-Agent`, `Origin`, `Referer`, `Host`
- `Location`, `Date`, `ETag`, `Last-Modified`

### Security Headers
- `DNT` (Do Not Track) → parsed as `bool`
- `Sec-GPC` → parsed as `bool`
- `Upgrade-Insecure-Requests` → parsed as `bool`

### Client Hints (Sec-CH-UA-*)
- `Sec-CH-UA` → parsed as list of `{'brand', 'version'}`
- `Sec-CH-UA-Mobile` → parsed as `bool`
- `Sec-CH-UA-Platform`, `Sec-CH-UA-Arch`, `Sec-CH-UA-Bitness`
- `Sec-CH-UA-Model`, `Sec-CH-UA-Full-Version`, `Sec-CH-UA-Full-Version-List`
- `Sec-CH-UA-Platform-Version`

### Fetch Metadata (Sec-Fetch-*)
- `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`

### Other
- `Priority` → parsed as dict
- `X-Requested-With`, `X-Forwarded-For`, `X-Real-IP`
- Any custom headers (stored as strings)

---

## Error Handling

```python
from parser_header import HeaderParser, CookieParser
from parser_header.exceptions import ParserError, InvalidHeaderError, EncodingError

# Missing value error
try:
    parser = HeaderParser()
    parser.set('Content-Type')  # Missing value!
except ValueError as e:
    print(f"Error: {e}")
    # Output: Error: value is required when name is provided

# Key not found
try:
    parser = HeaderParser()
    value = parser['nonexistent']
except KeyError as e:
    print(f"Error: {e}")
    # Output: Error: "Header 'nonexistent' not found"

# Encoding error (rare)
try:
    bad_bytes = b'\xff\xfe invalid'
    parser = HeaderParser(bad_bytes)
except EncodingError as e:
    print(f"Encoding failed: {e}")
```

---

## Development

```bash
# Clone repository
git clone https://github.com/cumulus13/parser_header.git
cd parser_header

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=parser_header --cov-report=term-missing

# Type checking
mypy parser_header

# Linting
ruff check parser_header

# Format code
black parser_header
```

---

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

**Hadi Cahyadi** - cumulus13@gmail.com

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)
