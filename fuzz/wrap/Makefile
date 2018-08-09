all: bin/fuzz_wrapper

bin/fuzz_wrapper: fuzz_wrapper.c
	mkdir -p bin
	gcc -m32 fuzz_wrapper.c -o bin/fuzz_wrapper -l:libcapstone.a

clean:
	rm -f bin/*
