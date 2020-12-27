# ezjail Cheatsheet

> Jail management made bearable.

## Table of Contents

* [Set CPU Affinity](#set-cpu-affinity)
* [Upgrade Base Jail](#upgrade-base-jail)
* [Disable Obsolete Warning](#disable-obsolete-warning)

### Disable Jail Autostart
```
ezjail-admin config -r norun <JAIL_NAME>
```

### Set CPU Affinity
You can limit the specific cores a jail uses but not a number of automatically 
scheduled ones. This can be done as a single core, a range of cores or a list 
cores.

```
ezjail-admin config -c <CORE_NUMBER> <JAIL_NAME>
```

Where `<CORE_NUMBER>` is the core number you want your jail on, with `0` being 
the first and `n-1` being the last should you have `n` cores, and `<JAIL_NAME>` 
being the name of the ezjail-managed jail you want to set the affinity of.

```
ezjail-admin config -c <CORE_NUMBER_FIRST>-<CORE_NUMBER_LAST> <JAIL_NAME>
```

Where `<CORE_NUMBER_FIRST>` and `<CORE_NUMBER_LAST>` are the first and last 
cores you want to run on respectively, and `<JAIL_NAME>` being the jail name.

```
ezjail-admin config -c <CORE_NUMBER_FIRST>,<CORE_NUMBER_SECOND>,...,<CORE_NUMBER_N> <JAIL_NAME>
```

Where core numbers like `<CORE_NUMBER_FIRST>`, `<CORE_NUMBER_LAST>`, and 
`<CORE_NUMBER_N>` are the core numbers you want to run on, and `<JAIL_NAME>` 
being the jail name.

### Upgrade Base Jail

There's a common issue arising every release upgrade with jails created in 
ezjail. The documentation is sparse in this regard. You'll know that you have a 
problem when you're running into the following error message:

> /!\ ERROR: /!\
>
> Ports Collection support for your FreeBSD version has ended, and no ports are
> guaranteed to build on this system. Please upgrade to a supported release.
>
> No support will be provided if you silence this message by defining
> ALLOW_UNSUPPORTED_SYSTEM.

Instead of just using the environment variable `ALLOW_UNSUPPORTED_SYSTEM`, find 
out what version of FreeeBSD you have running *inside of* the basejail:

```sh
grep FreeBSD_version /usr/include/sys/param.h
```

You'll get an output like the following:

```
#undef __FreeBSD_version
#define __FreeBSD_version 1101001       /* Master, propagated to newvers */
```

The first four numbers are what we're interested in, as they define the version 
currently in use — `10.1` in this case.

Now that you know the current version in use, you need to let `ezjail` upgrade 
*from* that version *to* the current host version. Since the kernel is shared 
between the host and jails, you cannot run a newer version of FreeBSD inside a 
jail than the host version.

To do so, run the following:

```sh
ezjail-admin update -U -s 11.1-RELEASE
```

Afterwards, restart all jails for good measure:

```sh
ezjail-admin restart
```

### Disable Obsolete Warning
> /etc/rc.d/jail: WARNING: Per-jail configuration via jail_* variables  is obsolete.  Please consider migrating to /etc/jail.conf.
```sh
sysrc jail_confwarn="NO"
```
