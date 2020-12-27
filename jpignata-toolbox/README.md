# Toolbox

Random command line tools I use day to day. Currently porting from various shell, Python, and Ruby scripts to Go for
portability.

## Tools

### aoc

Fetches input for an [Advent of Code][1] puzzle and prints it to `STDOUT`. If year is omitted, it defaults to the
current year.
#### Usage

`aoc day [year]`

```console
$ aoc 1 2016 | tee input.txt
R2, L1, R2, R1, R1, L3, R3, L5, L5, L2, L1, R4, R1, R3, L5, L5, R3, L4, L4, R5, R4, R3, L1, L2, R5, R4, L2, R1, R4, R4, L2, L1, L1, R190, R3, L4, R52, R5, R3, L5, R3, R2, R1, L5, L5, L4, R2, L3, R3, L1, L3, R5, L3, L4, R3, R77, R3, L2, R189, R4, R2, L2, R2, L1, R5, R4, R4, R2, L2, L2, L5, L1, R1, R2, L3, L4, L5, R1, L1, L2, L2, R2, L3, R3, L4, L1, L5, L4, L4, R3, R5, L2, R4, R5, R3, L2, L2, L4, L2, R2, L5, L4, R3, R1, L2, R2, R4, L1, L4, L4, L2, R2, L4, L1, L1, R4, L1, L3, L2, L2, L5, R5, R2, R5, L1, L5, R2, R4, R4, L2, R5, L5, R5, R5, L4, R2, R1, R1, R3, L3, L3, L4, L3, L2, L2, L2, R2, L1, L3, R2, R5, R5, L4, R3, L3, L4, R2, L5, R5
```

### gist

Posts the given files and/or input from `STDIN` as a [GitHub Gist][5]. Gists are private by default, but can be made
public via `-p`. Returns a link to the Gist.

#### Usage

`gist [-f <filename>] [-d <description>] [-n <name of stdin file>] [-p]`

```console
$ cat coolfile.txt | gist
https://gist.github.com/jpignata/0123456789abdefc0123456789abcdef

$ ./some-program | gist -n output.txt
https://gist.github.com/jpignata/0123456789abdefc0123456789abcdef

$ gist -f ./file.txt -d "Here's a file I have" -p
https://gist.github.com/jpignata/0123456789abdefc0123456789abcdef
```

### pf

[p]age [f]acts: returns pertinent details from an HTML page such as metadata
information, title, canonical URL, and alternate URLs.

#### Usage

`pf url`

```console
$ pf https://www.audible.com/pd/The-Three-Body-Problem-Audiobook/B00P0277C2
response             200 OK [connect=213.573152ms firstByte=268.282234ms total=268.41559ms]    
title                The Three-Body Problem (Audiobook) by Cixin Liu | Audible.com
h1                   The Three-Body Problem
description          Written by Cixin Liu, Audiobook narrated by Luke Daniels. Sign-in to download and listen to this audiobook today! First time visiting Audible? Get this book free when you sign up for a 30-day Trial.    
url                  https://www.audible.com/pd/The-Three-Body-Problem-Audiobook/B00P0277C2
canonical            https://www.audible.com/pd/The-Three-Body-Problem-Audiobook/B00P0277C2
alternate [en-za]    https://www.audible.com/pd/The-Three-Body-Problem-Audiobook/B01577B2Z2
alternate [en-nz]    https://www.audible.com.au/pd/The-Three-Body-Problem-Audiobook/B0157751UY
alternate [en-au]    https://www.audible.com.au/pd/The-Three-Body-Problem-Audiobook/B0157751UY
...
```

### urlcheck

Runs an HTTP HEAD request across URLs passed in through `STDIN`. The format of the file should be one URL per line. You
can optionally specify a max RPS (default 25) and number of workers (default 5).

#### Usage

`urlcheck [-max <requests>] [-workers <number>] < file`

```console
$ cat urls.txt | urlcheck
StatusCode:301 URL:http://www.arstechnica.com Location:https://www.arstechnica.com/
StatusCode:200 URL:https://www.nytimes.com
StatusCode:200 URL:https://www.audible.com

$ echo "https://www.google.com" | urlcheck
StatusCode:200 URL:https://www.google.com
```

### bitly

Shortens the given link and returns a [Bitlink][6].

#### Usage

`bitly [url]`

```console
$ bitly https://www.audible.com/pd/The-Three-Body-Problem-Audiobook/B00P027
https://adbl.co/2WPs8b7
```

## Dependencies

Tools that require authentication use [AWS System Manager][2] [Parameter Store][3] to fetch credentials. See
[pkg/ssm/secure_string.go][4] for details.

[1]: https://www.adventofcode.com
[2]: https://aws.amazon.com/systems-manager/
[3]: https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-paramstore.html
[4]: pkg/ssm/secure_string.go
[5]: https://gist.github.com
[6]: https://bit.ly
