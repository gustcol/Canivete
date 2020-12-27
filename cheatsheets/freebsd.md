# FreeBSD Cheatsheet

> The handbook is great, but this is the short one.

## Table of Contents

- [Boot](#boot)
- [File Systems](#file-systems)
- [Firewall](#firewall)
- [Hardware](#hardware)
- [Jails](#jails)
- [Kernel](#kernel)
- [Networking](#networking)
- [Permissions](#permissions)
- [pkgng](#pkgng)
- [Ports](#ports)
- [rc.d](#rcd)
- [Shell](#shell)
- [Software](#software)
- [Time](#time)
- [Updates](#updates)
- [ZFS](#zfs)

## Boot

### Reduce Boot-Time Delay
```sh
# /boot/loader.conf

autoboot_delay="3"
beastie_disable="YES"
```

## File Systems

### Create Sparse Image
`seek` specifies the size.
```sh
dd if=/dev/zero of=filesystem.img bs=1 seek=100G count=1
```

### Grow Sparse Image
```sh
dd if=/dev/zero of=filesystem.img bs=1 seek=200G count=1
```

### Create File System in Image
```sh
mdconfig filesystem.img
newfs -U /dev/md0
mount /dev/md0 /path/to/local/mnt
```

### Resize File System in Image
```sh
umount /dev/md0
mdconfig -d -u md0
dd if=/dev/zero of=filesystem.img bs=1 seek=200G count=1
mdconfig filesystem.img
growfs /dev/md0
mount /dev/md0 /path/to/local/mnt
```

### Mount/Unmount ISO File
```sh
## Mount
mkdir /media/cdrom
mdconfig -a -t vnode -f /path/to/iso/file
mount -t cd9660 /dev/md0 /media/cdrom

## Unmount
umount /media/cdrom
mdconfig -d -u md0
```

### Mount Linux EXT4 in LVM2
```sh
kldload /boot/kernel/geom_linux_lvm.ko
pkg install fusefs-ext4fuse
ext4fuse /dev/linux_lvm/volumegroup-logicalvolume /mnt
```

## Firewall

### Minimal Configuration
```
ext_if = "em0"
tcp_pass = "{ ssh }"
# net_jail="127.0.1.0/24"

# nat on $ext_if from $net_jail to any -> $ext_if

set skip on lo1
block in all
pass out all

pass in on $ext_if proto tcp to any port $tcp_pass keep state
pass inet proto icmp all icmp-type echoreq keep state
pass in quick proto icmp6 all
```

## Hardware

### Get Harddisk Information
```sh
camcontrol identify ada0
```

## Jails

### Completely Remove Jail Folders
```sh
chflags -R noschg /usr/jails && \
rm -rf /usr/jails
```

## Kernel

### Determining the Version of FreeBSD
In ascending level of obscurity, helpful when dealing with appliances based on FreeBSD.
```sh
freebsd-version
```

```sh
sysctl -n kern.osrelease kern.ostype
```

```sh
ident /boot/kernel/kernel
```

```sh
objdump -sj .data /boot/kernel/kernel | tail -n 22
```

### Install Kernel and System Sources
```sh
svnlite checkout https://svn.freebsd.org/base/release/11.1.0 /usr/src
```

## Networking

### Add Network Alias
```sh
# IPv4
ifconfig vtnet0 alias 10.80.0.67/32

# IPv6
ifconfig vtnet0 inet6 2610:1c1:0:4::3 prefixlen 64 alias
```
```
# /etc/rc.conf

ifconfig_em0_alias0="inet  10.80.0.67/32"
ifconfig_em0_alias1="inet6 2610:1c1:0:4::3 prefixlen 64"
```

### Check for Listening Ports
```sh
sockstat -46l | grep -E -e "\*:[[:digit:]]"
```

### Prevent resolv.conf from Being Overwritten
```sh
chflags schg /etc/resolv.conf
```

### Restart Network Service over SSH
```sh
/etc/rc.d/netif restart && /etc/rc.d/routing restart
```

### Mount Samba Share
```sh
mount_smbfs -I 10.20.30.40 //username@server/share /path/to/local/mnt
```

### Mount Samba Share with Credentials
```sh
# ~/.nsmbrc

[SERVER:USERNAME]
password=password
```
```sh
mount_smbfs -N -I 10.20.30.40 //username@server/share /path/to/local/mnt
```

### Set Default Route
```sh
route add default 10.20.30.1
```
```sh
# /etc/rc.conf

defaultrouter="10.20.30.1"
```

Confirm:
```sh
netstat -r
```

Command | Purpose
------- | -------
U	      | The route is active (up).
H	      | The route destination is a single host.
G	      | Send anything for this destination on to this gateway, which will figure out from there where to send it.
S	      | This route was statically configured.
C	      | Clones a new route based upon this route for machines to connect to. This type of route is normally used for local networks.
W	      | The route was auto-configured based upon a local area network (clone) route.
L	      | Route involves references to Ethernet (link) hardware.

#### Set Static IP Address for Interface
```
# /etc/rc.conf

hostname="freebsd.example.com"

### IPv4
ifconfig_em0="inet 192.168.0.6 netmask 255.255.255.0"
defaultrouter="192.168.0.254"

### IPv6 (multiple aliases possible)
ifconfig_em0_ipv6="inet6 2a03:4000:36:3f8::1/64"
ipv6_defaultrouter="fe80::1%em0"
```

## Permissions

### Make File Undeleteable, Even by Root
```sh
## Enable
chflags schg /path/to/file

## Disable
chflags noschg /path/to/file
```

## pkgng

### Fix Corrupt SQLite Database
Fixes "sqlite error while executing INSERT OR ROLLBACK INTO pkg_search".
```sh
pkg info -ao > pkglist.txt
rm /var/db/pkg/local.sqlite
pkg update -f
pkg install `cat pkglist.txt`
```

### List Installed Ports
```sh
pkg query --all '%o %n-%v %R'
```

## Ports

### Dump All Set Options
Prints out all previously set options in `make.conf` compatible format. Enables
creating pre-configured builds. Obviously only set the ones you absolutely
require, otherwise it will easily break on changes.
```sh
# process.sh

#!/bin/sh

FILE=$1
TMP=/tmp/process.tmp

NAME=`echo $FILE | sed -E 's#/var/db/ports/(.*)/.*#\1#'`

cat $FILE | \
    sed -E '/^_|^#/d' | \
    sed -E "s/OPTIONS_FILE/$NAME/" \
    > $TMP

cat $TMP
```

```sh
find '/var/db/ports/' -name 'options' -exec ./process.sh '{}' \;
```

## rc.d

### Sample Script

```sh
#!/bin/sh
#
# PROVIDE: fooapp
# REQUIRE: networking
# KEYWORD:

. /etc/rc.subr

name="fooapp"
rcvar="fooapp_enable"
fooapp_user="fooapp"
fooapp_command="/usr/local/fooapp/fooapp"
pidfile="/var/run/fooapp/${name}.pid"
command="/usr/sbin/daemon"
command_args="-P ${pidfile} -r -f ${fooapp_command}"

load_rc_config $name
: ${fooapp_enable:=no}

run_rc_command "$1"
```

Remember to create the `fooapp` user, the `pidfile` path and apply user permissions to it.

## Shell

### Clear csh History and Logout
```sh
echo > ~/.history && history -c && exit
```

## Software

### List Installed Ports/Packages
```sh
pkg query --all '%o %n-%v %R'
```

### Use CD-ROM Software Repository

First, either mount FreeBSD CD-ROM or ISO to `/dist`.

```sh
mkdir -p /usr/local/etc/pkg/repos
```

```sh
# /usr/local/etc/pkg/repos/cdrom.conf

cdrom: {
  url: "file:///dist/packages/${ABI}",
  mirror_type: "none",
  enabled: yes
}

FreeBSD: {
  enabled: no
}
```

```sh
pkg update
```

### Setup ccache
2 GB tmpfs
```sh
portmaster devel/ccache
mkdir /ram
echo 'none /ram tmpfs rw,size=2147483648 0 0' >> /etc/fstab
mount /ram
```

### Basic make.conf for Headless Servers
```
## ccache
WRKDIRPREFIX=/ram
CCACHE_DIR=/var/cache/ccache
WITH_CCACHE_BUILD=yes

## Build Optimizations
CPUTYPE?=native
OPTIONS_SET=OPTIMIZED_CFLAGS CPUFLAGS
BUILD_OPTIMIZED=YES

## Headless server options
OPTIONS_SET+=ICONV
OPTIONS_UNSET=CUPS DEBUG FONTCONFIG NLS X11
WITHOUT_MODULES=sound ntfs linux

## Disable sendmail
NO_SENDMAIL=true

## Fresh OpenSSL from Ports
DEFAULT_VERSIONS+=ssl=openssl
```

## Time

### Force Update Date and Time
If `ntpd` is installed:
```sh
service ntpd stop
ntpd -q -g
service ntpd start
```

With base `ntp`:
```sh
ntpdate -v -b in.pool.ntp.org
```

### Stop Listening on any Interface
```
# /etc/ntp.conf

interface ignore wildcard
```

### Set Timezone
```sh
ln -s /usr/share/zoneinfo/Asia/Calcutta /etc/localtime
```

## Updates

### Install portmaster
```sh
cd /usr/ports/ports-mgmt/portmaster && \
make install clean
```

### Install FreeBSD Ports Collection
```sh
portsnap fetch extract
```

### Upgrade FreeBSD Ports Collection
```sh
portsnap fetch update
```

### Fetch Binary Updates
```sh
freebsd-update fetch install
```

### Update FreeBSD from Source
For a new release:
```sh
mv /usr/src /usr/src.bak
svn checkout https://svn.freebsd.org/base/releng/11.1 /usr/src
```

Always:
```sh
svn update /usr/src
less /usr/src/UPDATING
cd /usr/src
make -j4 buildworld
make -j4 kernel
shutdown -r now
cd /usr/src
make installworld
mergemaster -Ui
shutdown -r now
```

## ZFS

### Create Pool from Image
```sh
zpool create tank /path/to/filesystem.img
```

### Mount Pool from Image
```sh
zpool import -d /path/to/folder/containing/filesystem.img tank
```

### Mount Pool with Different Root
Useful for untrusted pools or ones that mount to system directories.
```sh
zpool import -f -R /mnt pool
```

### Replace Failed ZFS-on-Root Disk
Usually those are mirrors, which is what those instructions are for. The assumed failed disk is `ada1`. Swap size could differ, check that before this action with `gpart show`.
```sh
zpool offline <FAILED_DISK>
zpool detach <FAILED_DISK>
# ...physically swap defective disk for a working disk...
gpart add -b 40 -l gptboot1 -s 512K -t freebsd-boot ada1
gpart add -s 16G -l swap1 -t freebsd-swap ada1
gpart add -t freebsd-zfs -l zfs1 ada1
zpool attach zroot ada0p3 ada1p3
gpart bootcode -b /boot/pmbr -p /boot/gptzfsboot -i 1 ada1
```

### Rescue ZFS-on-Root System
This comes in handy on `unable to remount devfs under dev` errors, for example. Reboot machine from USB/CD/network image. Select "Live System", then:
```sh
mkdir /tmp/mnt
zpool import -f -R /tmp/mnt zroot
zfs mount zroot/ROOT/default
chroot /tmp/mnt
# ...make changes...
exit
zpool export zroot
reboot
```

### Remount Read-Only Root ZFS Pool as Read-Write
```sh
zfs set readonly=off zroot
```
