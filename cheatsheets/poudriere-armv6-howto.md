# Poudriere ARMv6 Cross-Building Package Server How-to

The official binary packages for ARMv6 platforms (Raspberry Pi 1/2, etc.) are often out of date and some packages are not available at all. What's more, some packages refuse to compile without the system sources or won't compile at all. Here's how to supply your machines with fresh packages, configured to your needs.

## The Long Way

### Install

```sh
pkg install subversion qemu-user-static ccache poudriere
```

### Configure Poudriere

Change in `/usr/local/etc/poudriere.conf`:

```sh
ZPOOL=zroot
ZROOTFS=/poudriere
FREEBSD_HOST=http://download.FreeBSD.org
BASEFS=/usr/local/poudriere
POUDRIERE_DATA=${BASEFS}/data
NOLINUX=yes
USE_COLORS=yes
PRESERVE_TIMESTAMP=yes
BUILDER_HOSTNAME=build
WRKDIR_ARCHIVE_FORMAT=txz
```

### Configure QEMU

```sh
binmiscctl add armv6 \
    --interpreter "/usr/local/bin/qemu-arm-static" \
    --magic "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00" \
    --mask "\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff" \
    --size 20 \
    --set-enabled
```

### Create Jail

```sh
poudriere jail -c -j 11armv6 -m svn -a arm.armv6 -v release/11.0.1
```

### Install Default Ports Tree

```sh
poudriere ports -c
```

### Create Package List

`/usr/local/etc/poudriere.d/pkglist.txt`:

```
sysutils/ezjail
www/nginx
[...]
```

### Provision Package Options (Optional)

```sh
poudriere options -cf /usr/local/etc/poudriere.d/pkglist.txt
```

### Build

```sh
poudriere bulk -j 11armv6 -f /usr/local/etc/poudriere.d/pkglist.txt
```

### Create Repository Server

```sh
pkg install nginx
sysrc enable_nginx=YES
```

Add to `/usr/local/etc/nginx/nginx.conf`:

```nginx
server {
    listen       1.2.3.4:80;
    server_name  pkg.example.com;
    root         /usr/local/share/poudriere/html;

    # Allow caching static resources
    location ~* ^.+\.(jpg|jpeg|gif|png|ico|svg|woff|css|js|html)$ {
        add_header Cache-Control "public";
        expires 2d;
    }

    location /data {
        alias /usr/local/poudriere/data/logs/bulk;

        # Allow caching dynamic files but ensure they get rechecked
        location ~* ^.+\.(log|txz|tbz|bz2|gz)$ {
            add_header Cache-Control "public, must-revalidate, proxy-revalidate";
        }

        # Don't log json requests as they come in frequently and ensure
        # caching works as expected
        location ~* ^.+\.(json)$ {
            add_header Cache-Control "public, must-revalidate, proxy-revalidate";
            access_log off;
            log_not_found off;
        }

        # Allow indexing only in log dirs
        location ~ /data/?.*/(logs|latest-per-pkg)/ {
            autoindex on;
        }

        break;
    }

    location /repo {
        alias /usr/local/poudriere/data/packages;
    }
}
```

```sh
service nginx start
```

### Configure Clients to Use the Repository

```sh
mkdir -p /usr/local/etc/pkg/repos/
```

`/usr/local/etc/pkg/repos/Poudriere.conf`:

```
Poudriere: {
    url: "http://pkg.example.com/repo/11armv6-default",
    enabled: yes,
}
```

```sh
pkg update -f
```

### Update the Poudriere Ports Tree and Build Changes

```sh
poudriere ports -u
poudriere bulk -j 11armv6 -f /usr/local/etc/poudriere.d/pkglist.txt
```

## References

- <https://www.freebsd.org/doc/handbook/ports-poudriere.html>
- <https://www.dvatp.com/tech/armv6_freebsd_poudriere>
- <https://www.bsdnow.tv/tutorials/poudriere>
- <https://github.com/freebsd/poudriere/wiki/pkg_repos>
- <https://www.freebsd.org/cgi/man.cgi?query=binmiscctl&manpath=FreeBSD+11.0-RELEASE+and+Ports>
