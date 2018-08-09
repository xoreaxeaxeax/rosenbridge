all: bin/check_instruction

bin/check_instruction: check_instruction.c
	mkdir -p bin
	gcc -m32 check_instruction.c -o bin/check_instruction

clean:
	rm -f bin/*
