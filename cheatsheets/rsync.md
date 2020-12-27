# rsync Cheatsheet

> Incremental is the key.

## Table of Contents

- [Moving](#moving)

## Moving
It's possible to remove each source file after creating a successful copy, 
effectively moving the file.
```sh
rsync --remove-source-files /path/to/source/folder /path/to/destination/folder
```
