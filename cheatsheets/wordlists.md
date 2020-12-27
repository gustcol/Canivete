# Wordlists Cheatsheet

> Tools to deal with wordlists, yo.

## Cleaning

### Remove Lines Under n Characters
In this case, remove every line under 6 characters long.
```bash
sed -E '/^.{,6}$/d' /path/to/input/file > /path/to/output/file
```

If you encounter errors, use `gsed` like this:

```bash
gsed -E '/^.{,6}$/d' /path/to/input/file > /path/to/output/file
```

## Sorting

### Sort Alphabetically and Remove Duplicates
```bash
sort -us -o /path/to/output/file /path/to/input/file
```

If you encounter errors like `sort: mbrtowc error: Illegal byte sequence`, use `gsort` like this:

```bash
bash -c "LC_ALL='C' gsort -us -o /path/to/output/file /path/to/input/file"
```
