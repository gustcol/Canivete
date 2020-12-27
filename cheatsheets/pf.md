# pf Cheatsheet

> Forget iptables. Really.

## General pfctl Commands

```sh
# Disable Packet-Filtering
pfctl -d

# Enable Packet-Filtering
pfctl -e

# Run Quiet
pfctl -q

# Run Even More Verbose
pfctl -v
```

## Loading pf Rules

```sh
# Load /etc/pf.conf
pfctl -f /etc/pf.conf

# Parse /etc/pf.conf, but don't load it
pfctl -n -f /etc/pf.conf

# Load Only the FILTER Rules
pfctl -R -f /etc/pf.conf

# Load Only the NAT Rules
pfctl -N -f /etc/pf.conf

# Load Only the OPTION Rules
pfctl -O -f /etc/pf.conf
```

## Clearing PF Rules & Counters

```sh
# Flush All
pfctl -F all

# Flush only the Rules
pfctl -F rules

# Flush Only Queues
pfctl -F queue

# Flush Only NAT
pfctl -F nat

# Flush all Stats that are not Part of any Rule
pfctl -F info

# Clear all Counters
pfctl -z

### Note: flushing rules do not touch any existing stateful connections
```

## Output pf Information

```sh
# Show Filter Information:
pfctl -s rules

# show filter information for what FILTER rules hit
pfctl -v -s rules

# filter information as above and prepend rule numbers
pfctl -vvsr show

# show NAT information, for which NAT rules hit
pfctl -v -s nat

# show NAT information for interface xl1
pfctl -s nat -i xl1

# show QUEUE information
pfctl -s queue

# show LABEL information
pfctl -s label

# show contents of the STATE table
pfctl -s state

# show statistics for state tables and packet normalization
pfctl -s info

# show everything
pfctl -s all
```

## Maintaining pf Tables

```sh
# show table addvhosts
pfctl -t addvhosts -T show

# view global information about all tables
pfctl -vvsTables

# add entry to table addvhosts
pfctl -t addvhosts -T add 192.168.1.50

# add a network to table addvhosts
pfctl -t addvhosts -T add 192.168.1.0/16

# delete nework from table addvhosts
pfctl -t addvhosts -T delete 192.168.1.0/16

# remove all entries from table addvhosts
pfctl -t addvhosts -T flush

# delete table addvhosts entirely
pfctl -t addvhosts -T kill

# reload table addvhosts on the fly
pfctl -t addvhosts -T replace -f /etc/addvhosts

# find ip address 192.168.1.40 in table addvhosts
pfctl -t addvhosts -T test 192.168.1.40

# load a new table definition
pfctl -T load -f /etc/pf.conf

# output stats for each ip address in table addvhosts
pfctl -t addvhosts -T show -v

# reset all counters for table addvhosts
pfctl -t addvhosts -T zero
```

## Misc

```sh
# see live pf log
tcpdump -n -e -ttt -i pflog0

# list fail2ban jail contents
pfctl -a "f2b/nginx-badbots" -t f2b-nginx-badbots -Ts
```
