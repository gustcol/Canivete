# VirtualBox Cheatsheet

> Get the most out of open source virtualization.

## Table of Contents

- [Graphics](#graphics)

## Graphics

### Add More Graphics Memory
256 MB is the most supported by VirtualBox and not available via GUI.
```bash
VBoxManage modifyvm "Name of VM" --vram 256
```

### Add Custom Resolutions
```bash
VBoxManage setextradata "Name of VM" CustomVideoMode1 1600x900x32
```
