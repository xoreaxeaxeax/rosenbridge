/* runs a single deis instruction, used for testing */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PPC_RFI_BE_2 0x4c000064
#define PPC_RFI_LE_2 0x6400004c
#define PPC_RFI_BE_1 0x62000023
#define PPC_RFI_LE_1 0x23000062

#define INSTRUCTION  PPC_RFI_LE_1

typedef struct instruction_t {
	unsigned char prefix[3];
	unsigned int instruction;
} __attribute__ ((__packed__)) instruction_t;

int main(void) __attribute__ ((section (".check,\"awx\",@progbits#")));

instruction_t* bridge_indirect;

int main(void) 
{
	extern instruction_t _bridge;
	instruction_t* probe=&_bridge;
	unsigned int b;
	int i;

	instruction_t ins;

	ins.prefix[0]=0x8d;
	ins.prefix[1]=0x84;
	ins.prefix[2]=0x00;

	ins.instruction=INSTRUCTION;

	*probe=ins;

	printf("executing...\n");
	__asm__ __volatile__ ("\
			movl $_bridge, %%eax          \n\
			movl $_bridge, %%ebx          \n\
			movl $_bridge, %%ecx          \n\
			movl $_bridge, %%edx          \n\
			movl $_bridge, %%ebp          \n\
			movl $_bridge, %%esp          \n\
			movl $_bridge, %%esi          \n\
			movl $_bridge, %%edi          \n\
			.byte 0x0f, 0x3f              \n\
		_bridge:                          \n\
			.space 0x1000, 0x90           \n\
			"
			::
			);

	return 0;
}
