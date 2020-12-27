# Munin Cheatsheet

> Lightweight monitoring.

## Table of Contents

- [Node](#node)
- [Server](#server)

## Node

### FreeBSD

Install:

```bash
cd /usr/ports/sysutils/munin-node
make install clean
```

Configure:

```bash
munin-node-configure --shell --families=contrib,auto | sh -x
sysrc munin_node_enable=YES
sysrc munin_asyncd_enable=YES
service munin-node start
service munin-asyncd start
```

Run `vipw` and change the shell of the `munin` user from `/usr/sbin/nologin` to `/bin/sh`:

```
munin:*:842:842::0:0:Munin:/var/munin:/bin/sh
```

Change to `munin` user and set up SSH access:

```bash
su munin
mkdir /var/munin/.ssh
vi /var/munin/.ssh/authorized_keys
```

```
# /var/munin/.ssh/authorized_keys

no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc,from="1.2.3.4",command="/usr/local/share/munin/munin-async --spooldir /var/spool/munin/async --spoolfetch" ssh-ed25519 AAAA...
```
