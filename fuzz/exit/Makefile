all: bin/fuzz_exit 

bin/fuzz_exit: fuzz_exit.c
	mkdir -p bin
	gcc -m32 fuzz_exit.c -o bin/fuzz_exit

clean:
	rm -f bin/*
