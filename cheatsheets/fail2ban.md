# fail2ban Cheatsheet

> On the streets, saving the server from the forces of evil.

## FreeBSD

### Config

```sh
pkg install py27-fail2ban py27-pyinotify
```

```
# /etc/rc.conf

pf_enable="YES"
pflogd_enable="YES"
pf_rules="/etc/pf.conf"
fail2ban_enable="YES"
```

```
# /etc/pf.conf

# define macros for each network interface
ext_if = "em0"

icmp_types = "echoreq"
allproto = "{ tcp, udp, ipv6, icmp, esp, ipencap }"
privnets = "{ 127.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8 }"

set loginterface $ext_if

# Normalizes packets and masks the OS's shortcomings such as SYN/FIN packets 
# [scrub reassemble tcp](BID 10183) and sequence number approximation 
# bugs (BID 7487).
scrub in on $ext_if no-df random-id

# Anchor for fail2ban
anchor "f2b/*"
```

```
# /usr/local/etc/fail2ban/jail.local

[DEFAULT]
banaction = pf[actiontype=<allports>]
banaction = pf[actiontype=<multiport>]
backend = pyinotify
default_backend = pyinotify
ignoreip = 10.20.30.40/32 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
```

```
# /usr/local/etc/fail2ban/jail.d/ssh-pf.conf

[ssh-pf]
enabled = true
filter = bsd-sshd
logpath = /var/log/auth.log
findtime = 600
maxretry = 3
bantime  = 86400
```

### Show Banned IPs

```sh
pfctl -a "f2b/ssh-pf" -t f2b-ssh-pf -Ts
```

```sh
# ~/bin/showbans.sh

#!/bin/sh
#
# Show banned IPs in PF's 'fail2ban' table.

for i in `cat /usr/local/etc/fail2ban/jail.d/*.conf | grep -- -pf | sed 's/\[//' | sed 's/\]//'`; do
        echo ${i}
        pfctl -a "f2b/${i}" -t f2b-${i} -Ts
done

exit 0
```

### Remove Banned IP

```sh
fail2ban-client set ssh-pf unbanip 10.20.30.40
```
