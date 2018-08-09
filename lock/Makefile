all: bin/unlock bin/lock

bin/unlock: unlock.c
	mkdir -p bin
	gcc -m32 unlock.c -o bin/unlock

bin/lock: lock.c
	mkdir -p bin
	gcc -m32 lock.c -o bin/lock

clean:
	rm -f bin/*
