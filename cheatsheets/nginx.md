# Nginx Cheatsheet

> Can do it all — and does it.

## Table of Contents

- [Configuration](#configuration)
- [Rewrite](#rewrite)
- [SSL](#ssl)

## Configuration

### Prevent Crawlers from Indexing Certain Files
```
location ~ \.(m4v|oga|ogg|pdf)$ {
    try_files $uri $uri/;
    add_header X-Robots-Tag "noindex, nofollow, nosnippet, noarchive";
}
```

## Rewrite

### Subfolder to Proxy
This makes the application running at `127.0.1.1` available at `/api`. Check if
the application uses relative paths or expects to find itself at root level.
```
location /api {
    rewrite /api/(.*) /$1 break;
    proxy_pass http://127.0.1.1;
    proxy_redirect off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

```

## SSL

### Create a Snakeoil Certificate
Useful to configure a server config before getting a proper one, like Let's Encrypt.
```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /usr/local/etc/ssl/snakeoil.key -out /usr/local/etc/ssl/snakeoil.crt
```
