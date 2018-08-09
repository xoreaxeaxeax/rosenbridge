all: bin/fuzz_deis

bin/fuzz_deis: fuzz_deis.c
	mkdir -p bin
	gcc -m32 fuzz_deis.c -o bin/fuzz_deis

clean:
	rm -f bin/*
