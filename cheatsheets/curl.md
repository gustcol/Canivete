# curl Cheatsheet

> Request anything.

## Table of Contents

- [Headers](#headers)
- [Behavior](#behavior)

## Headers

### Print Response Headers
```sh
curl -s -D - -o /dev/null http://example.com
```

### Set User Agent String
```sh
curl -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15" http://example.com
```

### Set Custom Header
```sh
curl -H "Content-Type: application/json" http://example.com
```

## Behavior

### Follow Redirections
```sh
curl -L http://example.com
```
