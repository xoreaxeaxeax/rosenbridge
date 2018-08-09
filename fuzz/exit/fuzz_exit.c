#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_INSTRUCTIONS 100000

/* inline constraints will add a $ before an immediate, which .space will
 * refuse to parse = no inline constriants for the space piece.  can try to use
 * the preprocessor but it won't be able to resolve sizeof().  no good solution.
 * just hardcode the size. */
#define INSTRUCTION_SIZE 7 /* sizeof(instruction_t) */
#define PADDING (MAX_INSTRUCTIONS*INSTRUCTION_SIZE)

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

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

	printf("receiving...\n");
	printf(">\n"); /* signal to manager that we're ready for input */
	i=0;
	while (i<MAX_INSTRUCTIONS) {
		if (!scanf("%08x", &b)) {
			break;
		}
		ins.instruction=b;
		*probe++=ins;
		i++;
	}

	printf("(recieved %d instructions)\n", i);

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
			jmp *%%eax /* debug */        \n\
			"
			::
			);

	__asm__ __volatile__ ("\
		_bridge:                          \n\
			.space " STR(PADDING) ", 0x90 \n\
			"
			);

	printf("...i'm free...\n");

	printf(">\n"); /* signal to manager that we're done */

	return 0;
}
