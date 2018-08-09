#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>

#define BACKDOOR_MSR     0x00001107
#define BACKDOOR_TOGGLE  0x00000001

#define MSR_DEV "/dev/cpu/0/msr"

#if __x86_64__
	#define IP REG_RIP 
#else
	#define IP REG_EIP 
#endif

void sig_handler(int signum, siginfo_t* si, void* p)
{
	ucontext_t* uc=(ucontext_t*)p;
	uc->uc_mcontext.gregs[IP]+=2;
}

void configure_handler(void)
{
	struct sigaction s;

	s.sa_sigaction=sig_handler;
	s.sa_flags=SA_SIGINFO|SA_ONSTACK;

	sigfillset(&s.sa_mask);

	sigaction(SIGILL, &s, NULL);
}

volatile int pseudo_false=0;

int main(void)
{
	FILE* f;
	uint64_t v;

	f=fopen(MSR_DEV, "rb+");
	
	if (f==NULL) {
		printf("! failed to open %s\n", MSR_DEV);
		exit(-1);
	}

	/* unlock the backdoor */

	fseek(f, BACKDOOR_MSR, SEEK_SET);
	fread(&v, 8, 1, f);
	/* printf("read.... %08" PRIx64 "\n", v); */

	v|=BACKDOOR_TOGGLE;

	fseek(f, BACKDOOR_MSR, SEEK_SET);
	fwrite(&v, 8, 1, f);
	/* printf("wrote... %08" PRIx64 "\n", v); */

	fseek(f, BACKDOOR_MSR, SEEK_SET);
	fread(&v, 8, 1, f);
	/* printf("read.... %08" PRIx64 "\n", v); */

	fclose(f);

	/* check if the launch deis instruction is enabled */

	configure_handler();

	__asm__ ("movl $_bridge, %eax");
	__asm__ (".byte 0x0f, 0x3f");

	if (pseudo_false) { /* probably a better way to do this */
		__asm__ ("_bridge:");
		printf("executed hidden instruction: backdoor detected.\n");
	}
	else {
		printf("failed to execute hidden instruction: no backdoor detected.\n");
	}

	return 0;
}
