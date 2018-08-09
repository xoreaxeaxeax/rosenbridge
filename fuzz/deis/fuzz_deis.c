/* this program fuzzes deis instructions given a known wrapper */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <execinfo.h>
#include <limits.h>
#include <ucontext.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <assert.h>
#include <sched.h>
#include <pthread.h>
#include <sys/wait.h>

#define SIMULATE 0

#define TRACK_RING_0 1

//TODO: these are hacky (sorry)
#define USE_SEARCH_KERNEL 1
#define TARGET_KERNEL 1

#if TRACK_RING_0
#include "../../kern/privregs/privregs.h"
#define CR0_IGNORE_BITS 0x00000008
#endif

#if USE_SEARCH_KERNEL
#include "../../kern/deis_kernel.h"
#endif

typedef enum {
	INSTRUCTION_MODE_RANDOM,
	INSTRUCTION_MODE_SEED
} instruction_mode_t;
//instruction_mode_t MODE=INSTRUCTION_MODE_RANDOM;
instruction_mode_t MODE=INSTRUCTION_MODE_SEED;

#define MAX_SEED_INS 1000000
#include "seed_ins.h" /* selected from pattern extractor */
uint32_t seed_ins[MAX_SEED_INS];
int generated_seeded_ins;
#define SEEDS_PER_INSN 64
#define SEED_BITS 32
#define SEED_MASK 0x0fffffff /* don't flip masked bits */

#define LINE_BREAK "------------------------------------------------\n"
#define BUFFER_BYTES 32 /* must be > the number of fields in state_t + 7 */

#define BE(x) ((((x)>>24)&0x000000ff)|(((x)>>8)&0x0000ff00)|(((x)<<8)&0x00ff0000)|(((x)<<24)&0xff000000))

#define KEY_MARKER ". " /* prefix on lines that the log parser should keep */

#define RUN_TIMEOUT     1000000 /* useconds */
#define RESULT_TIMEOUT  50 /* runs */

/* delaying between each test gives time for the kernel logs to sync; fuzzing
 * bottleneck is in the reboots, not in this program, we can sleep as long as we
 * want with virtually no impact on throughput */
#define FUZZ_DELAY 500000  /* useconds, < RUN_TIMEOUT */

typedef struct instruction_t {
	unsigned char prefix[3];
	unsigned int deis;
} __attribute__ ((__packed__)) instruction_t;

typedef struct {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t esp;
	union {
		uint64_t mm0;
		struct {
			uint32_t mm0l;
			uint32_t mm0h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm1;
		struct {
			uint32_t mm1l;
			uint32_t mm1h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm2;
		struct {
			uint32_t mm2l;
			uint32_t mm2h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm3;
		struct {
			uint32_t mm3l;
			uint32_t mm3h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm4;
		struct {
			uint32_t mm4l;
			uint32_t mm4h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm5;
		struct {
			uint32_t mm5l;
			uint32_t mm5h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm6;
		struct {
			uint32_t mm6l;
			uint32_t mm6h;
		} __attribute__ ((__packed__));
	};
	union {
		uint64_t mm7;
		struct {
			uint32_t mm7l;
			uint32_t mm7h;
		} __attribute__ ((__packed__));
	};
	uint32_t eflags;
#if TRACK_RING_0
	uint32_t cr0;
	uint32_t cr2;
	uint32_t cr3;
	uint32_t cr4;
	uint32_t dr0;
	uint32_t dr1;
	uint32_t dr2;
	uint32_t dr3;
	uint32_t dr4;
	uint32_t dr5;
	uint32_t dr6;
	uint32_t dr7;
#endif
} state_t;

typedef struct {
	uint8_t data[BUFFER_BYTES];
} mem_t;

typedef enum {
	MEMORY_NOCHANGE,
	MEMORY_RANDOM,
	MEMORY_PATTERN,
	MEMORY_KERNEL,
} mem_init_t;

typedef enum {
	STATE_NOCHANGE,
	STATE_RANDOM,
	STATE_MEMORY,
	STATE_PATTERN,
	STATE_KERNEL,
} state_init_t;

typedef enum {
#if USE_SEARCH_KERNEL
	SEARCH_KERNEL,
#endif
#if TARGET_KERNEL
	SEARCH_END,
#endif
	SEARCH_MEMORY,
	SEARCH_STATE,
#if !TARGET_KERNEL
	SEARCH_END,
#endif
} search_t;

typedef enum {
	RUN_0,
#if TARGET_KERNEL
	RUN_END,
#endif
	RUN_1,
	RUN_2,
	RUN_3,
#if !TARGET_KERNEL
	RUN_END,
#endif
} run_t;

/* some issues with asm constraints if these are local */
state_t input_state, working_state, output_state;
mem_t input_mem, output_mem;

uint64_t* run_tick; /* shared */
uint64_t* result_tick; /* shared */

int main(void);
unsigned long long llrand(void);
void initialize_state(state_t*, state_init_t, mem_t*, mem_init_t);
bool states_equal(state_t*, state_t*);
bool memory_equal(mem_t*, mem_t*);
void print_instruction(instruction_t*);
void fuzz(void);
void inject(void) __attribute__ ((section (".check,\"awx\",@progbits#")));

void initialize_state(
		state_t* state,
		state_init_t state_init,
		mem_t* mem,
		mem_init_t mem_init
		)
{
	int i;

#if USE_SEARCH_KERNEL
	uintptr_t kernel_buffer;
	int handle;
#endif

	switch (state_init) {
		case STATE_NOCHANGE:
			break;
		case STATE_RANDOM:
			state->eax=llrand();
			state->ebx=llrand();
			state->ecx=llrand();
			state->edx=llrand();
			state->esi=llrand();
			state->edi=llrand();
			state->ebp=llrand();
			state->esp=llrand();
			state->mm0=llrand();
			state->mm1=llrand();
			state->mm2=llrand();
			state->mm3=llrand();
			state->mm4=llrand();
			state->mm5=llrand();
			state->mm6=llrand();
			state->mm7=llrand();
			break;
		case STATE_MEMORY:
			state->eax=(uintptr_t)&mem->data[0];
			state->ebx=(uintptr_t)&mem->data[1];
			state->ecx=(uintptr_t)&mem->data[2];
			state->edx=(uintptr_t)&mem->data[3];
			state->esi=(uintptr_t)&mem->data[4];
			state->edi=(uintptr_t)&mem->data[5];
			state->ebp=(uintptr_t)&mem->data[6];
			state->esp=(uintptr_t)&mem->data[7];
			state->mm0=(uintptr_t)&mem->data[8];
			state->mm1=(uintptr_t)&mem->data[9];
			state->mm2=(uintptr_t)&mem->data[10];
			state->mm3=(uintptr_t)&mem->data[11];
			state->mm4=(uintptr_t)&mem->data[12];
			state->mm5=(uintptr_t)&mem->data[13];
			state->mm6=(uintptr_t)&mem->data[14];
			state->mm7=(uintptr_t)&mem->data[15];
			break;
#if USE_SEARCH_KERNEL
		case STATE_KERNEL:
			handle=open("/dev/deis_kernel", O_RDWR);
			ioctl(handle, GET_BUFFER_ADDRESS, &kernel_buffer);
			//TODO: temp - initialize to 0
			/*
			state->eax=kernel_buffer+0;
			state->ebx=kernel_buffer+1;
			state->ecx=kernel_buffer+2;
			state->edx=kernel_buffer+3;
			state->esi=kernel_buffer+4;
			state->edi=kernel_buffer+5;
			state->ebp=kernel_buffer+6;
			state->esp=kernel_buffer+7;
			state->mm0=kernel_buffer+8;
			state->mm1=kernel_buffer+9;
			state->mm2=kernel_buffer+10;
			state->mm3=kernel_buffer+11;
			state->mm4=kernel_buffer+12;
			state->mm5=kernel_buffer+13;
			state->mm6=kernel_buffer+14;
			state->mm7=kernel_buffer+15;
			*/
			state->eax=0;
			state->ebx=0;
			state->ecx=0;
			state->edx=0;
			state->esi=0;
			state->edi=0;
			state->ebp=0;
			state->esp=0;
			state->mm0=0;
			state->mm1=0;
			state->mm2=0;
			state->mm3=0;
			state->mm4=0;
			state->mm5=0;
			state->mm6=0;
			state->mm7=0;
			close(handle);
			break;
#endif
		case STATE_PATTERN:
			state->eax=0x00000000;
			state->ebx=0x11111111;
			state->ecx=0x22222222;
			state->edx=0x33333333;
			state->esi=0x44444444;
			state->edi=0x55555555;
			state->ebp=0x66666666;
			state->esp=0x77777777;

			state->mm0=0x8888888888888888ull;
			state->mm1=0x9999999999999999ull;
			state->mm2=0xaaaaaaaaaaaaaaaaull;
			state->mm3=0xbbbbbbbbbbbbbbbbull;
			state->mm4=0xccccccccccccccccull;
			state->mm5=0xddddddddddddddddull;
			state->mm6=0xeeeeeeeeeeeeeeeeull;
			state->mm7=0xffffffffffffffffull;
			break;
		default:
			assert(0);
	}

	switch (mem_init) {
		case MEMORY_NOCHANGE:
			break;
		case MEMORY_PATTERN:
			for (i=0; i<BUFFER_BYTES; i++) {
				mem->data[i]=0x11*(i%16);
			}
			break;
		case MEMORY_RANDOM:
			for (i=0; i<BUFFER_BYTES; i++) {
				mem->data[i]=rand();
			}
			break;
#if USE_SEARCH_KERNEL
		case MEMORY_KERNEL:
			/* nothing to initialize */
			break;
#endif
		default:
			assert(0);
	}
}

#if TRACK_RING_0
void load_ring_0_state(state_t* state)
{
	int handle;
	privregs_req_t req;

	handle=open("/dev/privregs", O_RDWR);

	req=(privregs_req_t){0, 0};
	ioctl(handle, READ_DR, &req);
	state->dr0=req.val;

	req=(privregs_req_t){1, 0};
	ioctl(handle, READ_DR, &req);
	state->dr1=req.val;

	req=(privregs_req_t){2, 0};
	ioctl(handle, READ_DR, &req);
	state->dr2=req.val;

	req=(privregs_req_t){3, 0};
	ioctl(handle, READ_DR, &req);
	state->dr3=req.val;

	req=(privregs_req_t){4, 0};
	ioctl(handle, READ_DR, &req);
	state->dr4=req.val;

	req=(privregs_req_t){5, 0};
	ioctl(handle, READ_DR, &req);
	state->dr5=req.val;

	req=(privregs_req_t){6, 0};
	ioctl(handle, READ_DR, &req);
	state->dr6=req.val;

	req=(privregs_req_t){7, 0};
	ioctl(handle, READ_DR, &req);
	state->dr7=req.val;

	req=(privregs_req_t){0, 0};
	ioctl(handle, READ_CR, &req);
	state->cr0=req.val;

	req=(privregs_req_t){2, 0};
	ioctl(handle, READ_CR, &req);
	state->cr2=req.val;

	req=(privregs_req_t){3, 0};
	ioctl(handle, READ_CR, &req);
	state->cr3=req.val;

	req=(privregs_req_t){4, 0};
	ioctl(handle, READ_CR, &req);
	state->cr4=req.val;

	close(handle);
}
#endif

unsigned long long llrand(void)
{
	int i;
	unsigned long long r=0;
	for (i=0; i<5; ++i) {
		r = (r<<15)|(rand()&0x7FFF);
	}
	return r&0xFFFFFFFFFFFFFFFFULL;
}

void print_binary(uint32_t x)
{
	int i;
	for (i=0; i<32; i++) {
		if (i && i%4==0) {
			printf(" ");
		}
		printf("%d", x>>31);
		x<<=1;
	}
}

void print_instruction(instruction_t* ins)
{
	printf("L(%08x)", ins->deis);

	printf(" ");
	printf("B(%08x)", BE(ins->deis));

	printf("  ");
	printf("L(");
	print_binary(ins->deis);
	printf(")");
	printf(" ");
	printf("B(");
	print_binary(BE(ins->deis));
	printf(")");
	printf("\n");
	fflush(stdout);
}

void print_gpr_state_headers(void)
{
	printf("%-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s\n",
			"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp");
}

void print_mmx_0_3_state_headers(void)
{
	printf("%-18s  %-18s  %-18s  %-18s\n",
			"mm0", "mm1", "mm2", "mm3");
}

void print_mmx_4_7_state_headers(void)
{
	printf("%-18s  %-18s  %-18s  %-18s\n",
			"mm4", "mm5", "mm6", "mm7");
}

void print_gpr_state(state_t* state)
{
	printf("%08x  ", state->eax);
	printf("%08x  ", state->ebx);
	printf("%08x  ", state->ecx);
	printf("%08x  ", state->edx);
	printf("%08x  ", state->esi);
	printf("%08x  ", state->edi);
	printf("%08x  ", state->ebp);
	printf("%08x  ", state->esp);
	printf("\n");
}

void print_byte_diff(uint8_t* x, uint8_t* y, int len, char* spacing_1, char* spacing_4)
{
	int i;
	for (i=0; i<len; i++) {
		if (i&&i%4==0) {
			printf("%s", spacing_4);
		}
		if (x[len-i-1]!=y[len-i-1]) {
			printf("^^");
		}
		else {
			printf("  ");
		}
		printf("%s", spacing_1);
	}
	if (i&&i%4==0) {
		printf("%s", spacing_4);
	}
}

void print_gpr_state_diff(state_t* state_1, state_t* state_2)
{
	print_byte_diff((uint8_t*)&state_1->eax, (uint8_t*)&state_2->eax, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->ebx, (uint8_t*)&state_2->ebx, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->ecx, (uint8_t*)&state_2->ecx, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->edx, (uint8_t*)&state_2->edx, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->esi, (uint8_t*)&state_2->esi, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->edi, (uint8_t*)&state_2->edi, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->ebp, (uint8_t*)&state_2->ebp, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->esp, (uint8_t*)&state_2->esp, 4, "", "  ");
	printf("\n");
}

void print_mmx_0_3_state_diff(state_t* state_1, state_t* state_2)
{
	print_byte_diff((uint8_t*)&state_1->mm0, (uint8_t*)&state_2->mm0, 8, "", "  ");
	print_byte_diff((uint8_t*)&state_1->mm1, (uint8_t*)&state_2->mm1, 8, "", "  ");
	print_byte_diff((uint8_t*)&state_1->mm2, (uint8_t*)&state_2->mm2, 8, "", "  ");
	print_byte_diff((uint8_t*)&state_1->mm3, (uint8_t*)&state_2->mm3, 8, "", "  ");
	printf("\n");
}

void print_mmx_4_7_state_diff(state_t* state_1, state_t* state_2)
{
	print_byte_diff((uint8_t*)&state_1->mm4, (uint8_t*)&state_2->mm4, 8, "", "  ");
	print_byte_diff((uint8_t*)&state_1->mm5, (uint8_t*)&state_2->mm5, 8, "", "  ");
	print_byte_diff((uint8_t*)&state_1->mm6, (uint8_t*)&state_2->mm6, 8, "", "  ");
	print_byte_diff((uint8_t*)&state_1->mm7, (uint8_t*)&state_2->mm7, 8, "", "  ");
	printf("\n");
}

void print_mmx_0_3_state(state_t* state)
{
	printf("%08x  %08x  ", state->mm0h, state->mm0l);
	printf("%08x  %08x  ", state->mm1h, state->mm1l);
	printf("%08x  %08x  ", state->mm2h, state->mm2l);
	printf("%08x  %08x  ", state->mm3h, state->mm3l);
	printf("\n");
}

void print_mmx_4_7_state(state_t* state)
{
	printf("%08x  %08x  ", state->mm4h, state->mm4l);
	printf("%08x  %08x  ", state->mm5h, state->mm5l);
	printf("%08x  %08x  ", state->mm6h, state->mm6l);
	printf("%08x  %08x  ", state->mm7h, state->mm7l);
	printf("\n");
}

void print_memory_headers(void)
{
	int i;
	for (i=0; i<sizeof(mem_t); i++) {
		if (i>0 && i%4==0) {
			printf(" ");
		}
		if (i%4==0) {
			printf("%02x ", i);
		}
		else {
			printf("   ");
		}
	}
	printf("\n");
}

void print_memory(mem_t* mem)
{
	int i;
	for (i=0; i<sizeof(mem_t); i++) {
		if (i>0 && i%4==0) {
			printf(" ");
		}
		printf("%02x ", mem->data[i]);
	}
	printf("\n");
}

void print_memory_diff_summary(mem_t* mem_1, mem_t* mem_2)
{
	int i;
	for (i=0; i<sizeof(mem_t); i++) {
		if (i>0 && i%4==0) {
			printf(" ");
		}
		if (mem_1->data[i]!=mem_2->data[i]) {
			printf("^^ ");
		}
		else {
			printf("   ");
		}
	}
	printf("\n");
}

bool states_equal(state_t* state_1, state_t* state_2)
{
	return 
		state_1->eax==state_2->eax &&
		state_1->ebx==state_2->ebx &&
		state_1->ecx==state_2->ecx &&
		state_1->edx==state_2->edx &&
		state_1->esi==state_2->esi &&
		state_1->edi==state_2->edi &&
		state_1->ebp==state_2->ebp &&
		state_1->esp==state_2->esp &&
		state_1->mm0==state_2->mm0 &&
		state_1->mm1==state_2->mm1 &&
		state_1->mm2==state_2->mm2 &&
		state_1->mm3==state_2->mm3 &&
		state_1->mm4==state_2->mm4 &&
		state_1->mm5==state_2->mm5 &&
		state_1->mm6==state_2->mm6 &&
		state_1->mm7==state_2->mm7
#if TRACK_RING_0
		&&
		(state_1->cr0&~CR0_IGNORE_BITS)==(state_2->cr0&~CR0_IGNORE_BITS) &&
		state_1->cr2==state_2->cr2 &&
		state_1->cr3==state_2->cr3 &&
		state_1->cr4==state_2->cr4 &&
		state_1->dr0==state_2->dr0 &&
		state_1->dr1==state_2->dr1 &&
		state_1->dr2==state_2->dr2 &&
		state_1->dr3==state_2->dr3 &&
		state_1->dr4==state_2->dr4 &&
		state_1->dr5==state_2->dr5 &&
		state_1->dr6==state_2->dr6 &&
		state_1->dr7==state_2->dr7
#endif
		;
}

bool memory_equal(mem_t* mem_1, mem_t* mem_2)
{
	return (memcmp(mem_1,mem_2,sizeof(mem_t))==0);
}

void inject(void)
{
#if USE_SEARCH_KERNEL
	int handle;
	handle=open("/dev/deis_kernel", O_RDWR);
	ioctl(handle, READ_BUFFER, &input_mem.data);
	close(handle);
#endif

#if TRACK_RING_0
	load_ring_0_state(&input_state);
#endif

	__asm__ __volatile__ ("\
			pushfl                        \n\
			popl %[input_eflags]          \n\
			"
			: [input_eflags]"=m"(input_state.eflags)
			: 
			);

	__asm__ __volatile__ ("\
			movl %%eax, %[working_eax]    \n\
			movl %%ebx, %[working_ebx]    \n\
			movl %%ecx, %[working_ecx]    \n\
			movl %%edx, %[working_edx]    \n\
			movl %%esi, %[working_esi]    \n\
			movl %%edi, %[working_edi]    \n\
			movl %%ebp, %[working_ebp]    \n\
			movl %%esp, %[working_esp]    \n\
			"
			: /* set to input registers to work around gcc error */
			  /*
			  [working_eax]"+m"(working_state.eax),
			  [working_ebx]"+m"(working_state.ebx),
			  [working_ecx]"+m"(working_state.ecx),
			  [working_edx]"+m"(working_state.edx),
			  [working_esi]"+m"(working_state.esi),
			  [working_edi]"+m"(working_state.edi),
			  [working_ebp]"+m"(working_state.ebp),
			  [working_esp]"+m"(working_state.esp)
			  */
			: [working_eax]"m"(working_state.eax),
			  [working_ebx]"m"(working_state.ebx),
			  [working_ecx]"m"(working_state.ecx),
			  [working_edx]"m"(working_state.edx),
			  [working_esi]"m"(working_state.esi),
			  [working_edi]"m"(working_state.edi),
			  [working_ebp]"m"(working_state.ebp),
			  [working_esp]"m"(working_state.esp)
			);

	__asm__ __volatile__ ("\
			movq %%mm0, %[working_mm0]    \n\
			movq %%mm1, %[working_mm1]    \n\
			movq %%mm2, %[working_mm2]    \n\
			movq %%mm3, %[working_mm3]    \n\
			movq %%mm4, %[working_mm4]    \n\
			movq %%mm5, %[working_mm5]    \n\
			movq %%mm6, %[working_mm6]    \n\
			movq %%mm7, %[working_mm7]    \n\
			"
			: /* set to input registers to work around gcc error */
			: [working_mm0]"m"(working_state.mm0),
			  [working_mm1]"m"(working_state.mm1),
			  [working_mm2]"m"(working_state.mm2),
			  [working_mm3]"m"(working_state.mm3),
			  [working_mm4]"m"(working_state.mm4),
			  [working_mm5]"m"(working_state.mm5),
			  [working_mm6]"m"(working_state.mm6),
			  [working_mm7]"m"(working_state.mm7)
			);

	__asm__ __volatile__ ("\
			movq %[input_mm0], %%mm0    \n\
			movq %[input_mm1], %%mm1    \n\
			movq %[input_mm2], %%mm2    \n\
			movq %[input_mm3], %%mm3    \n\
			movq %[input_mm4], %%mm4    \n\
			movq %[input_mm5], %%mm5    \n\
			movq %[input_mm6], %%mm6    \n\
			movq %[input_mm7], %%mm7    \n\
			"
			: 
			: [input_mm0]"m"(input_state.mm0),
			  [input_mm1]"m"(input_state.mm1),
			  [input_mm2]"m"(input_state.mm2),
			  [input_mm3]"m"(input_state.mm3),
			  [input_mm4]"m"(input_state.mm4),
			  [input_mm5]"m"(input_state.mm5),
			  [input_mm6]"m"(input_state.mm6),
			  [input_mm7]"m"(input_state.mm7)
			);

	__asm__ __volatile__ ("\
			movl %[input_eax], %%eax      \n\
			movl %[input_ebx], %%ebx      \n\
			movl %[input_ecx], %%ecx      \n\
			movl %[input_edx], %%edx      \n\
			movl %[input_esi], %%esi      \n\
			movl %[input_edi], %%edi      \n\
			movl %[input_ebp], %%ebp      \n\
			movl %[input_esp], %%esp      \n\
		debug:                            \n\
			"
#if !SIMULATE
			"\
			.byte 0x0f, 0x3f              \n\
			"
#else
			"\
			movl $0xdeadbeef, (%%edx)     \n\
			movw $0x1337, %%cx            \n\
			movq (_bridge), %%mm0         \n\
			"
#endif
			"\
		_bridge:                          \n\
			.space 0x1000, 0x90           \n\
										  \n\
			movl %%eax, %[output_eax]     \n\
			movl %%ebx, %[output_ebx]     \n\
			movl %%ecx, %[output_ecx]     \n\
			movl %%edx, %[output_edx]     \n\
			movl %%esi, %[output_esi]     \n\
			movl %%edi, %[output_edi]     \n\
			movl %%ebp, %[output_ebp]     \n\
			movl %%esp, %[output_esp]     \n\
										  \n\
			"
			: /* set as input registers to work around gcc error */
			  /*
			  [output_eax]"+m"(output_state.eax),
			  [output_ebx]"+m"(output_state.ebx),
			  [output_ecx]"+m"(output_state.ecx),
			  [output_edx]"+m"(output_state.edx),
			  [output_esi]"+m"(output_state.esi),
			  [output_edi]"+m"(output_state.edi),
			  [output_ebp]"+m"(output_state.ebp),
			  [output_esp]"+m"(output_state.esp)
			  */
			: [output_eax]"m"(output_state.eax),
			  [output_ebx]"m"(output_state.ebx),
			  [output_ecx]"m"(output_state.ecx),
			  [output_edx]"m"(output_state.edx),
			  [output_esi]"m"(output_state.esi),
			  [output_edi]"m"(output_state.edi),
			  [output_ebp]"m"(output_state.ebp),
			  [output_esp]"m"(output_state.esp),
			  [input_eax]"m"(input_state.eax),
			  [input_ebx]"m"(input_state.ebx),
			  [input_ecx]"m"(input_state.ecx),
			  [input_edx]"m"(input_state.edx),
			  [input_esi]"m"(input_state.esi),
			  [input_edi]"m"(input_state.edi),
			  [input_ebp]"m"(input_state.ebp),
			  [input_esp]"m"(input_state.esp)
			);

	__asm__ __volatile__ ("\
			movq %%mm0, %[output_mm0]    \n\
			movq %%mm1, %[output_mm1]    \n\
			movq %%mm2, %[output_mm2]    \n\
			movq %%mm3, %[output_mm3]    \n\
			movq %%mm4, %[output_mm4]    \n\
			movq %%mm5, %[output_mm5]    \n\
			movq %%mm6, %[output_mm6]    \n\
			movq %%mm7, %[output_mm7]    \n\
			"
			: /* set to input registers to work around gcc error */
			: [output_mm0]"m"(output_state.mm0),
			  [output_mm1]"m"(output_state.mm1),
			  [output_mm2]"m"(output_state.mm2),
			  [output_mm3]"m"(output_state.mm3),
			  [output_mm4]"m"(output_state.mm4),
			  [output_mm5]"m"(output_state.mm5),
			  [output_mm6]"m"(output_state.mm6),
			  [output_mm7]"m"(output_state.mm7)
			);

	__asm__ __volatile__ ("\
			movl %[working_eax], %%eax    \n\
			movl %[working_ebx], %%ebx    \n\
			movl %[working_ecx], %%ecx    \n\
			movl %[working_edx], %%edx    \n\
			movl %[working_esi], %%esi    \n\
			movl %[working_edi], %%edi    \n\
			movl %[working_ebp], %%ebp    \n\
			movl %[working_esp], %%esp    \n\
			"
			:
			: [working_eax]"m"(working_state.eax),
			  [working_ebx]"m"(working_state.ebx),
			  [working_ecx]"m"(working_state.ecx),
			  [working_edx]"m"(working_state.edx),
			  [working_esi]"m"(working_state.esi),
			  [working_edi]"m"(working_state.edi),
			  [working_ebp]"m"(working_state.ebp),
			  [working_esp]"m"(working_state.esp)
			);

	__asm__ __volatile__ ("\
			movq %[working_mm0], %%mm0    \n\
			movq %[working_mm1], %%mm1    \n\
			movq %[working_mm2], %%mm2    \n\
			movq %[working_mm3], %%mm3    \n\
			movq %[working_mm4], %%mm4    \n\
			movq %[working_mm5], %%mm5    \n\
			movq %[working_mm6], %%mm6    \n\
			movq %[working_mm7], %%mm7    \n\
			"
			:
			: [working_mm0]"m"(working_state.mm0),
			  [working_mm1]"m"(working_state.mm1),
			  [working_mm2]"m"(working_state.mm2),
			  [working_mm3]"m"(working_state.mm3),
			  [working_mm4]"m"(working_state.mm4),
			  [working_mm5]"m"(working_state.mm5),
			  [working_mm6]"m"(working_state.mm6),
			  [working_mm7]"m"(working_state.mm7)
			);

	__asm__ __volatile__ ("\
			pushfl                        \n\
			popl %[output_eflags]         \n\
			"
			: [output_eflags]"=m"(output_state.eflags)
			: 
			);

#if TRACK_RING_0
	load_ring_0_state(&output_state);
#endif

#if USE_SEARCH_KERNEL
	handle=open("/dev/deis_kernel", O_RDWR);
	ioctl(handle, READ_BUFFER, &output_mem.data);
	close(handle);
#endif
}

float frand(void)
{
	return ((float)(rand()%RAND_MAX))/(RAND_MAX-1);
}

void generate_seeded_list(void)
{
	int i;
	generated_seeded_ins=0;
	for (
		i=0;
		i<sizeof seed_ins_source/sizeof *seed_ins_source && i<MAX_SEED_INS;
		i++
		) {
		int k;
		for (k=0; k<SEEDS_PER_INSN; k++) {
			uint32_t ins=seed_ins_source[i];
			int j;
			float p=1;
			for (j=0; j<SEED_BITS; j++) {
				if (frand()<p) {
					unsigned int b;
					do {
						b=rand()%32;
					} while (!((1<<b)&SEED_MASK));
					ins^=(1<<b);
				}
				p/=2;
			}
			seed_ins[generated_seeded_ins]=ins;
			/* printf("%08x\n", ins); */
			generated_seeded_ins++;
		}
	}
}

uint32_t get_seeded(void)
{
	return seed_ins[llrand()%generated_seeded_ins];
}

void configure(
		instruction_mode_t mode,
		search_t search,
		run_t run,
		instruction_t* ins,
		state_t* input_state,
		state_t* output_state,
		mem_t* input_mem,
		mem_t* output_mem
		)
{
	state_init_t run_0_state_init;

#if USE_SEARCH_KERNEL
	int handle;
	handle=open("/dev/deis_kernel", O_RDWR);
	ioctl(handle, RESET_BUFFER, NULL);
	close(handle);
#endif

	if (search==SEARCH_STATE) {
		run_0_state_init=STATE_RANDOM;
	}
	else if (search==SEARCH_MEMORY) {
		run_0_state_init=STATE_MEMORY;
	}
#if USE_SEARCH_KERNEL
	else if (search==SEARCH_KERNEL) {
		run_0_state_init=STATE_KERNEL;
	}
#endif
	else {
		assert (0);
	}

	if (run==RUN_0) {
		/* first run */
		if (mode==INSTRUCTION_MODE_RANDOM) {
			ins->deis=llrand();
		}
		else if (mode==INSTRUCTION_MODE_SEED) {
			ins->deis=get_seeded();
		}
		else {
			assert (0);
		}
		initialize_state(
				input_state,
				run_0_state_init,
				output_mem, /* memory_init will make pointers to this
				               buffer */
#if USE_SEARCH_KERNEL
				search==SEARCH_KERNEL?MEMORY_KERNEL:MEMORY_PATTERN
#else
				MEMORY_PATTERN
#endif
				);
		//TODO: maybe this is more cleanly put in inject, where the register
		//state is recorded
		*input_mem=*output_mem; /* record initial state */
	}
	else if (run==RUN_1) {
		/* second run */
		/* repeat previous run */
		*output_mem=*input_mem; /* reset target memory */
	}
	else if (run==RUN_2) {
		/* third run */
		/* run on a different randomized state */
		initialize_state(
				input_state,
				STATE_RANDOM,
				output_mem,
				MEMORY_NOCHANGE
				);
		*output_mem=*input_mem; /* reset target memory */
	}
	else if (run==RUN_3) {
		/* fourth run */
		/* run on a patterned register state */
		initialize_state(
				input_state,
				STATE_PATTERN,
				output_mem,
				MEMORY_NOCHANGE
				);
		*output_mem=*input_mem; /* reset target memory */
	}
	else {
		assert(0);
	}
}

void print_memory_diff(mem_t* input, mem_t* output)
{
	printf(KEY_MARKER);
	printf("        ");
	print_memory_headers();
	printf(KEY_MARKER);
	printf("inject: ");
	print_memory(&input_mem);
	printf(KEY_MARKER);
	printf("result: ");
	print_memory(&output_mem);
	printf(KEY_MARKER);
	printf("        ");
	print_memory_diff_summary(input, output);
}

#if TRACK_RING_0

void print_dr_state_headers(void)
{
	printf("%-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s\n",
			"dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7");
}

void print_dr_state(state_t* state)
{
	printf("%08x  ", state->dr0);
	printf("%08x  ", state->dr1);
	printf("%08x  ", state->dr2);
	printf("%08x  ", state->dr3);
	printf("%08x  ", state->dr4);
	printf("%08x  ", state->dr5);
	printf("%08x  ", state->dr6);
	printf("%08x  ", state->dr7);
	printf("\n");
}

void print_dr_state_diff(state_t* state_1, state_t* state_2)
{
	print_byte_diff((uint8_t*)&state_1->dr0, (uint8_t*)&state_2->dr0, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr1, (uint8_t*)&state_2->dr1, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr2, (uint8_t*)&state_2->dr2, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr3, (uint8_t*)&state_2->dr3, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr4, (uint8_t*)&state_2->dr4, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr5, (uint8_t*)&state_2->dr5, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr6, (uint8_t*)&state_2->dr6, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->dr7, (uint8_t*)&state_2->dr7, 4, "", "  ");
	printf("\n");
}

void print_cr_state_headers(void)
{
	printf("%-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s\n",
			"cr0", "", "cr2", "cr3", "cr4", "", "", "");
}

void print_cr_state(state_t* state)
{
	printf("%08x  ", state->cr0);
	printf("%8s  ", "");
	printf("%08x  ", state->cr2);
	printf("%08x  ", state->cr3);
	printf("%08x  ", state->cr4);
	printf("%8s  ", "");
	printf("%8s  ", "");
	printf("%8s  ", "");
	printf("\n");
}

void print_cr_state_diff(state_t* state_1, state_t* state_2)
{
	print_byte_diff((uint8_t*)&state_1->cr0, (uint8_t*)&state_2->cr0, 4, "", "  ");
	printf("%8s  ", "");
	print_byte_diff((uint8_t*)&state_1->cr2, (uint8_t*)&state_2->cr2, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->cr3, (uint8_t*)&state_2->cr3, 4, "", "  ");
	print_byte_diff((uint8_t*)&state_1->cr4, (uint8_t*)&state_2->cr4, 4, "", "  ");
	printf("%8s  ", "");
	printf("%8s  ", "");
	printf("%8s  ", "");
	printf("\n");
}
#endif

void print_state_diff(state_t* input, state_t* output)
{
	printf(KEY_MARKER);
	printf("        ");
	print_gpr_state_headers();
	printf(KEY_MARKER);
	printf("inject: ");
	print_gpr_state(input);
	printf(KEY_MARKER);
	printf("result: ");
	print_gpr_state(output);
	printf(KEY_MARKER);
	printf("        ");
	print_gpr_state_diff(input, output);

	printf(KEY_MARKER);
	printf("        ");
	print_mmx_0_3_state_headers();
	printf(KEY_MARKER);
	printf("inject: ");
	print_mmx_0_3_state(input);
	printf(KEY_MARKER);
	printf("result: ");
	print_mmx_0_3_state(output);
	printf(KEY_MARKER);
	printf("        ");
	print_mmx_0_3_state_diff(input, output);

	printf(KEY_MARKER);
	printf("        ");
	print_mmx_4_7_state_headers();
	printf(KEY_MARKER);
	printf("inject: ");
	print_mmx_4_7_state(input);
	printf(KEY_MARKER);
	printf("result: ");
	print_mmx_4_7_state(output);
	printf(KEY_MARKER);
	printf("        ");
	print_mmx_4_7_state_diff(input, output);

	printf(KEY_MARKER);
	printf("        %-8s\n", "eflags");
	printf(KEY_MARKER);
	printf("inject: %08x\n", input->eflags);
	printf(KEY_MARKER);
	printf("result: %08x\n", output->eflags);
	printf(KEY_MARKER);
	printf("        ");
	print_byte_diff((uint8_t*)&input->eflags, (uint8_t*)&output->eflags, 4, "", "  ");
	printf("\n");

#if TRACK_RING_0
	printf(KEY_MARKER);
	printf("        ");
	print_cr_state_headers();
	printf(KEY_MARKER);
	printf("inject: ");
	print_cr_state(input);
	printf(KEY_MARKER);
	printf("result: ");
	print_cr_state(output);
	printf(KEY_MARKER);
	printf("        ");
	print_cr_state_diff(input, output);

	printf(KEY_MARKER);
	printf("        ");
	print_dr_state_headers();
	printf(KEY_MARKER);
	printf("inject: ");
	print_dr_state(input);
	printf(KEY_MARKER);
	printf("result: ");
	print_dr_state(output);
	printf(KEY_MARKER);
	printf("        ");
	print_dr_state_diff(input, output);
#endif
}

void fuzz(void)
{
	extern instruction_t _bridge;
	instruction_t* probe=&_bridge;
	instruction_t ins;
	run_t run;
#if !TARGET_KERNEL
	search_t search=rand()%SEARCH_END;
#else
	search_t search=SEARCH_KERNEL;
#endif
	bool found_change;

	ins.prefix[0]=0x62;
	ins.prefix[1]=0x04;
	ins.prefix[2]=0x05;

	run=RUN_0;
	while (1) {
		(*run_tick)++;

		printf(">" LINE_BREAK);
		if (search==SEARCH_STATE) {
			printf("(search state)\n");
		}
		else if (search==SEARCH_MEMORY) {
			printf("(search memory)\n");
		}
#if USE_SEARCH_KERNEL
		else if (search==SEARCH_KERNEL) {
			printf("(search kernel)\n");
		}
#endif
		else {
			assert (0);
		}
		printf("(run %d)\n", run);

		configure(
				MODE,
				search,
				run,
				&ins,
				&input_state,
				&output_state,
				&input_mem,
				&output_mem
				);
		input_state.eax=(uintptr_t)&_bridge;
#if !SIMULATE
		*probe=ins;
#endif

		printf(KEY_MARKER);
		print_instruction(&ins);

		printf("executing...\n");
		fflush(stdout); /* always flush before running the deis */

		inject();

		printf("...done.\n");

		(*result_tick)++;

		found_change=false;

		if (!memory_equal(&input_mem,&output_mem)||!states_equal(&input_state,&output_state)) {
			found_change=true;
			printf("\n");
			print_memory_diff(&input_mem, &output_mem);
			print_state_diff(&input_state,&output_state);
		}

		/* determine next run based on results */
		if (found_change) {
			run++;
			if (run==RUN_END) {
				/* move to next search strategy */
				run=RUN_0;
				search=(search+1)%SEARCH_END;
			}
		}
		else {
			/* no change detected */
			if (run==RUN_0) {
				/* no run started */
				/* move to next search strategy */
				search=(search+1)%SEARCH_END;
			}
			else {
				/* run started, continue */
				run++;
				if (run==RUN_END) {
					/* move to next search strategy */
					run=RUN_0;
					search=(search+1)%SEARCH_END;
				}
			}
		}

		printf("<" LINE_BREAK);
		fflush(stdout);

		usleep(FUZZ_DELAY);
	}
}

int main(void) 
{
	int pid;
	unsigned int seed;
	int failed_runs=0;

	run_tick=mmap(NULL, sizeof *run_tick, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	result_tick=mmap(NULL, sizeof *result_tick, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	*run_tick=0;

	generate_seeded_list();
	
	while (1) {
		*result_tick=0;

		pid=fork();

		if (pid==0) {
			seed=time(NULL)*(*run_tick+1);
			srand(seed);
			printf("fuzzing (seed: %08x)...\n", seed);
			fuzz();
		}
		else {
			/* parent */
			uint64_t last_run_tick=-1;

			while (1) {
				usleep(RUN_TIMEOUT);
				if (last_run_tick==*run_tick) {
					printf("killing %d\n", pid);
					fflush(stdout);
					kill(pid, SIGKILL);
					if (*result_tick==0) {
						/* produced no result */
						failed_runs++;
						if (failed_runs>RESULT_TIMEOUT) {
							/* sometimes system gets into state where the forked
							 * process _always_ fails.  give up after n times;
							 * the controller will reset us when it sees we are
							 * no longer producing output */
							printf("failed to execute %d times\n", failed_runs);
							printf("quitting\n");
							exit(-1);
						}
					}
					else {
						failed_runs=0;
					}
					break;
				}
				else {
					last_run_tick=*run_tick;
				}
			}
		}
	}

	return 0;
}
