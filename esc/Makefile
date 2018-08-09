all: bin/escalate

bin/escalate: escalate.c payload.asm
	mkdir -p bin
	python ../asm/deis_asm.py payload.asm > bin/payload.h
	gcc -m32 escalate.c -o bin/escalate

clean:
	rm -f bin/*
