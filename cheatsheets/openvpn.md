# OpenVPN Cheatsheet

> VPN for smart people.

## Install and Configure on FreeBSD 11

### Load Kernel Module

Load into active session:
```bash
kldload if_tun
```

To load again on boot, add to `/boot/loader.conf`:
```conf
if_tun_load="YES"
```

### Install OpenVPN

```bash
cd /usr/ports/security/openvpn
make install clean
```

### Make it Start Automatically on Boot

```bash
sysrc openvpn_enable="YES"
sysrc openvpn_configfile="/usr/local/etc/openvpn/server.conf"
```

### Create Server Configuration

```bash
mkdir /usr/local/etc/openvpn
cp /usr/local/share/examples/openvpn/sample-config-files/server.conf /usr/local/etc/openvpn/server.conf
```

### Generate Server Certificates and Keys

```bash
cp -r /usr/local/share/easy-rsa /usr/local/etc/openvpn/easy-rsa
cd /usr/local/etc/openvpn/easy-rsa
vi vars
source vars
./easyrsa.real init-pki
./easyrsa.real gen-dh
./easyrsa.real build-ca
./easyrsa.real build-server-full server
```

### Copy the Key Files and Certificates

```bash
cp /usr/local/etc/openvpn/easy-rsa/pki/dh.pem /usr/local/etc/openvpn/dh2048.pem
cp /usr/local/etc/openvpn/easy-rsa/pki/ca.crt /usr/local/etc/openvpn
cp /usr/local/etc/openvpn/easy-rsa/pki/private/server.key /usr/local/etc/openvpn
cp /usr/local/etc/openvpn/easy-rsa/pki/issued/server.crt /usr/local/etc/openvpn
```

### Create TLS Key

```bash
openvpn --genkey --secret /usr/local/etc/openvpn/ta.key
```

### Remove Passphrase from Private Key

```bash
openssl rsa -in /usr/local/etc/openvpn/server.key -out /usr/local/etc/openvpn/server.key
```

### Set Firewall Rules

```
# /etc/pf.conf

### Interfaces
ext_if = "bge0"
vpn_if = "tun0"
vpn_net="10.8.1.0/24"

nat on $ext_if inet from $vpn_net to any -> $ext_if

pass in on $ext_if proto udp to ($ext_if) port 1194
pass in on $vpn_if from any to any

block in
pass out
```

### Enable Firewall on Boot

```
# /etc/rc.conf

gateway_enable="YES"
pf_enable="YES"
pf_rules="/etc/pf.conf"
```

### Enable IP Forwarding

``` bash
sysctl net.inet.ip.forwarding=1
```

### Load Firewall Rules and Enable

```bash
pfctl -ef /etc/pf.conf
```

### Edit Configuration, Test and Start

```bash
ee /usr/local/etc/openvpn/server.conf
openvpn --config /usr/local/etc/openvpn/server.conf
service openvpn start
```

### Generate Client Certificate

```bash
cd /usr/local/etc/openvpn/easy-rsa
./easyrsa.real build-client-full client1
```

### Generate Client Configuration

```bash
#!/bin/sh

CLIENTNAME="client1"

cat << EOF >> $CLIENTNAME.ovpn
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
key-direction 1
EOF

echo "<ca>" >> $CLIENTNAME.ovpn
cat /usr/local/etc/openvpn/easy-rsa/pki/ca.crt >> $CLIENTNAME.ovpn
echo "</ca>" >> $CLIENTNAME.ovpn
echo "<cert>" >> $CLIENTNAME.ovpn
cat /usr/local/etc/openvpn/easy-rsa/pki/issued/$CLIENTNAME.crt >> $CLIENTNAME.ovpn
echo "</cert>" >> $CLIENTNAME.ovpn
echo "<key>" >> $CLIENTNAME.ovpn
cat /usr/local/etc/openvpn/easy-rsa/pki/private/$CLIENTNAME.key >> $CLIENTNAME.ovpn
echo "</key>" >> $CLIENTNAME.ovpn
echo "<tls-auth>" >> $CLIENTNAME.ovpn
cat /usr/local/etc/openvpn/ta.key >> $CLIENTNAME.ovpn
echo "</tls-auth>" >> $CLIENTNAME.ovpn
```
