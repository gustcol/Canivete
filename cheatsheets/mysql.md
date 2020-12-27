# MySQL Cheatsheet

> Archaic command reference.

## Create Database
``` sql
CREATE DATABASE foobar;
```

## Create New User
``` sql
CREATE USER 'user'@'localhost' IDENTIFIED BY 'foobar';
```

## Change User Password
``` sql
SET PASSWORD FOR 'user'@'localhost' = PASSWORD('foobar'); FLUSH PRIVILEGES;
```

## List Databases
``` sql
SHOW DATABASES;
```

## List Users
``` sql
SELECT host, user, password FROM mysql.user;
```

## Rename Tables
Run this on the shell.
```bash
for table in `mysql -u root -s -N -e "show tables from <OLD_DATABASE>"`; do
    mysql -u root -s -N -e "rename table <OLD_DATABASE>.$table to <NEW_DATABASE>.$table";
done;
```

## Set User Privileges
``` sql
GRANT ALL PRIVILEGES ON foobar.* TO 'user'@'localhost'; FLUSH PRIVILEGES;
```

## Good Default Config
MariaDB 10 on FreeBSD.
``` ini
[mysql]

# CLIENT #
port                           = 3306
socket                         = /var/db/mysql/mysql.sock

[mysqld]

# GENERAL #
user                           = mysql
default-storage-engine         = InnoDB
socket                         = /var/db/mysql/mysql.sock
pid-file                       = /var/db/mysql/mysql.pid

# MyISAM #
key-buffer-size                = 32M
myisam-recover                 = FORCE,BACKUP

# SAFETY #
max-allowed-packet             = 16M
max-connect-errors             = 1000000
skip-name-resolve
sql-mode                       = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_AUTO_VALUE_ON_ZERO,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,ONLY_FULL_GROUP_BY
sysdate-is-now                 = 1
innodb                         = FORCE
innodb-strict-mode             = 1

# DATA STORAGE #
datadir                        = /var/db/mysql/

# BINARY LOGGING #
log-bin                        = /var/db/mysql/mysql-bin
expire-logs-days               = 14
sync-binlog                    = 1

# CACHES AND LIMITS #
tmp-table-size                 = 32M
max-heap-table-size            = 32M
query-cache-type               = 0
query-cache-size               = 0
max-connections                = 500
thread-cache-size              = 50
open-files-limit               = 65535
table-definition-cache         = 4096
table-open-cache               = 4096

# INNODB #
innodb-flush-method            = O_DIRECT
innodb-log-files-in-group      = 2
innodb-log-file-size           = 64M
innodb-flush-log-at-trx-commit = 1
innodb-file-per-table          = 1
innodb-buffer-pool-size        = 128M

# LOGGING #
log-error                      = /var/db/mysql/mysql-error.log
log-queries-not-using-indexes  = 1
slow-query-log                 = 1
slow-query-log-file            = /var/db/mysql/mysql-slow.log
```

## Optimizing

- [MySQLTuner](https://github.com/major/MySQLTuner-perl)
