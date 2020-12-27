.PHONY: install clean

all: bin/aoc bin/gist bin/pf bin/urlcheck bin/bitly

install: all
	cp bin/* ~/bin

clean:
	rm -f bin/*

bin/aoc:
	go build -o bin/aoc aoc/main.go

bin/gist:
	go build -o bin/gist gist/main.go

bin/pf:
	go build -o bin/pf pf/main.go

bin/urlcheck:
	go build -o bin/urlcheck urlcheck/main.go

bin/bitly:
	go build -o bin/bitly bitly/main.go
