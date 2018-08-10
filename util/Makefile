all: bin/check

bin/check: check.c
	mkdir -p bin
	gcc -no-pie check.c -o ./bin/check

clean:
	rm -f bin/*
