# OpenSSH Cheatsheet

> The secure shell.

## Table of Contents

- [Configuration](#ssh-configuration)
- [Key Management](#key-management)

## Configuration

### Multiple SSH Hops
```
# ~/.ssh/config

Host bastion
    Hostname bastion.domain.com
    User bastion-user

Host server
    Hostname server.local.lan
    User server-user
    ProxyCommand ssh bastion -W %h:%p
```

### Restrict SSH User Access
```bash
# ~/.ssh/authorized_keys

from="10.20.30.0/24,44.55.66.77",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,command="/usr/local/bin/whatever" ssh-rsa [...]
```

## Key Management

### Create Secure SSH Key
```bash
ssh-keygen -o -a 100 -t ed25519
```
