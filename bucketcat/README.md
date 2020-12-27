# bucketcat
Brute-forces objects within a given bucket using Hashcat mask-like syntax

> But why?

Because occasionally you'll come across AWS keys that can S3:GetObject but not S3:ListBucket

> Does that really happen that often?

Nope.

> So then again.... why

Because I needed to take a break from everything else I'm doing and find an excuse to write some good ol' Python.

#### Usage
```
usage: bucketcat.py [-h] [-m MASK | -f INFILE] [-k CREDSFILE] [-p PROFILE]
                    [-b BUCKET] [-t THREADS] [-o OUTFILE] [-s] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -m MASK, --mask MASK  Hashcat-like mask for S3 objects
  -f INFILE, --infile INFILE
                        File with multiple Hashcat-like masks
  -k CREDSFILE, --credsfile CREDSFILE
                        File with the AWS credentials to use. Defaults to .env
  -p PROFILE, --profile PROFILE
                        AWS profile to use.
  -b BUCKET, --bucket BUCKET
                        Target bucket
  -t THREADS, --threads THREADS
                        Number of threads to run with. Defaults to 1.
  -o OUTFILE, --outfile OUTFILE
                        Outfile to dump results to. Defaults to stdout.
  -s, --server          Run as a server in distributed mode (not yet
                        supported)
  -c, --client          Run as a client in distributed mode (not yet
                        supported)
```

### hcmask files

bucketcat uses Hashcat mask-like syntax for generating payloads. For example, this mask would generate all possible three-letter filenames ending in .txt:

```
?l?l?l.txt
```

The current character sets are supported by default:

| Key | Characters |
| --- | --- | 
| ?l | All lowercase letters |
| ?u | All uppercase letters |
| ?d | All digits |
| ?s | All special chars (via `string.punctuation`) |
| ?a | All characters (via `string.printable`) |

Custom characters sets can be created as well, but require passing in file instead of an individual mask:

```
python3 bucketcat.py -f test.hcmask -b atticusstestbucket
```

And the contents of test.hcmask:

```
?1 0123456789abcdef
x?1?1.txt
```

This creates a new key `?1` assigned to 0-9 and a-f. This example would generate all S3 keys in the form of `x00.txt` through `xff.txt`. Note: all user-created character sets must use a digit (e.g `?1`). This is to allow hcmask files to search for "?a foobar" without overwriting the `?a` set.

### TODO

* Add support for distributed brute-forcing via the `--server` and `--client` flags.