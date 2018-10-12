all: bin/check

bin/check: check.c
	mkdir -p bin
	gcc check.c -o ./bin/check -no-pie -fno-pie

clean:
	rm -f bin/*
