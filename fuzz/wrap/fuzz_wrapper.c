#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
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

#include <capstone/capstone.h>

//TODO: maybe a solution is to simply fuzz 1 byte at a time... pick a first
//byte, fuzz that for 100k instructions, see what happens.  then pick a new
//first byte, repeat.  helps to separate out effects - no more uncertainty about
//who caused the corruption.

//TODO: unicorn support
//TODO: mmx registers
//TODO: alternatively to unicorn ... could try running the same thing with that
//bit disabled, and comparing system states ... it's probably faster and more
//reliable than unicorn, with the downside of risking that turning that bit off
//doesn't really switch it out of the special state
//*could even fork, execute one version with bit off one with bit on, and
//compare MEMORY state too
//TODO: could profile really quickly to see where you waste your time, should be
//able to get many more tests

#define DEBUG 0
#define GDB 0

csh capstone_handle;
cs_insn *capstone_insn;

#define STR(x) #x
#define XSTR(x) STR(x)

//#define START_PREFIX 0x6200 /* temp - don't want to start all over */
//#define PREFIX_LENGTH 2
#define START_PREFIX 0x620400 /* temp - don't want to start all over */
#define PREFIX_LENGTH 3

#if 0
#define TICK_MASK 0xf /* 0xfff */
#define PREFIX_TICK 100 /* 10000 */
#endif
//#define TICK_MASK 0xff /* 0xfff */
#define TICK_MASK 1 /* 0xfff */
//#define PREFIX_TICK 10000 /* 10000 */
#define PREFIX_TICK 10000 /* 10000 */
#define TIMEOUT   10000
#define KILL 1

#define UD2_SIZE  2
#define PAGE_SIZE 4096
#define TF        0x100

typedef struct {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t esp;
} state_t;
state_t inject_state={
	.eax=0,
	.ebx=0,
	.ecx=0,
	.edx=0,
	.esi=0,
	.edi=0,
	.ebp=0,
	.esp=0,
};

struct {
	uint64_t dummy_stack_hi[256];
	uint64_t dummy_stack_lo[256];
} dummy_stack __attribute__ ((aligned(PAGE_SIZE)));

void* packet;

static char stack[SIGSTKSZ];
stack_t ss = { .ss_size = SIGSTKSZ, .ss_sp = stack, };

#define MAX_INSN_LENGTH 15 /* actually 15 */

/* fault handler tries to use fault address to make an initial guess of
 * instruction length; but length of jump instructions can't be determined from
 * trap alone */
/* set to this if something seems wrong */
#define JMP_LENGTH 16 

typedef struct {
	uint8_t bytes[MAX_INSN_LENGTH];
	int len; /* the number of specified bytes in the instruction */
} insn_t;
insn_t insn;

mcontext_t fault_context;

typedef struct __attribute__ ((packed)) {
	uint32_t valid;
	uint32_t signum;
	uint32_t si_code;
	uint32_t addr;
} result_t;
result_t result;

/* functions */

void preamble(void);
void inject(void);
void state_handler(int, siginfo_t*, void*);
void fault_handler(int, siginfo_t*, void*);
void configure_sig_handler(void (*)(int, siginfo_t*, void*));
void generate_instruction(void);
unsigned long long llrand(void);
void initialize_state(void);
void fuzz(void);
bool is_prefix(uint8_t);
bool has_opcode(uint8_t*);
bool has_prefix(uint8_t*);

extern char debug, resume, preamble_start, preamble_end;

uint64_t* counter; /* shared */
uint64_t* prefix; /* shared */

/* blacklists */

#define MAX_BLACKLIST 128

typedef struct {
	char* opcode;
	char* reason;
} ignore_op_t;

ignore_op_t opcode_blacklist[MAX_BLACKLIST]={
	//{ "\x62", "bound" }, /* suspect */
	{ "\x71", "jcc" }, /* temp, causing too many kills */
	{ "\x72", "jcc" },
	{ "\x73", "jcc" },
	{ "\x74", "jcc" },
	{ "\x75", "jcc" },
	{ "\x76", "jcc" },
	{ "\x77", "jcc" },
	{ "\x78", "jcc" },
	{ "\x79", "jcc" },
	{ "\x7a", "jcc" },
	{ "\x7b", "jcc" },
	{ "\x7c", "jcc" },
	{ "\x7d", "jcc" },
	{ "\x7e", "jcc" },
	{ "\x7f", "jcc" },
	{ "\xcd\x80", "int80" },
	{ "\xdf", "float" }, /* suspect */
	{ "\xdb", "float" }, /* suspect */
	{ "\xde", "fdivp" }, /* suspect */
	{ "\xe2", "loop" }, /* causing too many kills */
	{ "\xeb", "jmp" }, /* causing too many kills */
	{ NULL, NULL }
};

void initialize_capstone(void)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &capstone_handle) != CS_ERR_OK) {
		exit(1);
	}
	capstone_insn = cs_malloc(capstone_handle);
}

int get_instruction_length(void)
{
	uint8_t* code=insn.bytes;
	size_t code_size=MAX_INSN_LENGTH;
	uint64_t address=(uintptr_t)packet;

	if (cs_disasm_iter(
			capstone_handle,
			(const uint8_t**)&code,
			&code_size,
			&address,
			capstone_insn)
		) {
		/*
		printf(
			"%10s %-45s (%2d)",
			capstone_insn[0].mnemonic,
			capstone_insn[0].op_str,
			(int)(address-(uintptr_t)packet)
			);
		*/
	}
	return (int)(address-(uintptr_t)packet);
}

/* this becomes hairy with "mandatory prefix" instructions */
bool is_prefix(uint8_t x)
{
	return 
		x==0xf0 || /* lock */
		x==0xf2 || /* repne / bound */
		x==0xf3 || /* rep */
		x==0x2e || /* cs / branch taken */
		x==0x36 || /* ss / branch not taken */
		x==0x3e || /* ds */
		x==0x26 || /* es */
		x==0x64 || /* fs */
		x==0x65 || /* gs */
		x==0x66 || /* data */
		x==0x67    /* addr */
#if __x86_64__
		|| (x>=0x40 && x<=0x4f) /* rex */
#endif
		;
}

//TODO: can't blacklist 00
bool has_opcode(uint8_t* op)
{
	int i, j;
	for (i=0; i<MAX_INSN_LENGTH; i++) {
		if (!is_prefix(insn.bytes[i])) {
			j=0;
			do {
				if (i+j>=MAX_INSN_LENGTH || op[j]!=insn.bytes[i+j]) {
					return false;
				}
				j++;
			} while (op[j]);

			return true;
		}
	}
	return false;
}

//TODO: can't blacklist 00
bool has_prefix(uint8_t* pre)
{
	int i, j;
	for (i=0; i<MAX_INSN_LENGTH; i++) {
		if (is_prefix(insn.bytes[i])) {
			j=0;
			do {
				if (insn.bytes[i]==pre[j]) {
					return true;
				}
				j++;
			} while (pre[j]);
		}
		else {
			return false;
		}
	}
	return false;
}

void print_insn(insn_t* insn)
{
	int i;
	for (i=0; i<sizeof(insn->bytes); i++) {
		printf("%02x", insn->bytes[i]);
	}
	printf("\n");
	fflush(stdout);
}

/* gcc doesn't allow naked inline, i hate it */
void preamble(void)
{
	__asm__ __volatile__ ("\
			.global preamble_start                    \n\
			preamble_start:                           \n\
			pushfl                                    \n\
			orl %0, (%%esp)                           \n\
			popfl                                     \n\
			.global preamble_end                      \n\
			preamble_end:                             \n\
			"
			:
			:"i"(TF)
			);
}

unsigned long long llrand(void)
{
	int i;
	unsigned long long r=0;
	for (i=0; i<5; ++i) {
		r = (r<<15)|(rand()&0x7FFF);
	}
	return r&0xFFFFFFFFFFFFFFFFULL;
}

void initialize_state(void)
{
	inject_state=(state_t){
		.eax=llrand(),
		.ebx=llrand(),
		.ecx=llrand(),
		.edx=llrand(),
		.esi=llrand(),
		.edi=llrand(),
		.ebp=llrand(),
		/* .esp=llrand(), */
		.esp=(uintptr_t)&dummy_stack.dummy_stack_lo,
	};
}

uint8_t cleanup[]={0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x0f, 0x0b};

void inject(void)
{
	int i;
	int preamble_length=(&preamble_end-&preamble_start);
	static bool have_state=false;

	initialize_state();

	//TODO: testing without preamble
	preamble_length=0;

	for (i=0; i<preamble_length; i++) {
		((char*)packet)[i]=((char*)&preamble_start)[i];
	}
	for (i=0; i<MAX_INSN_LENGTH; i++) {
		((char*)packet)[i+preamble_length]=insn.bytes[i];
	}

	//TODO: testing without preamble
	for (i=0; i<sizeof(cleanup); i++) {
		((char*)packet)[i+MAX_INSN_LENGTH]=cleanup[i];
	}

	dummy_stack.dummy_stack_lo[0]=0;

	if (!have_state) {
		/* optimization: only get state first time */
		have_state=true;
		configure_sig_handler(state_handler);
		__asm__ __volatile__ ("ud2\n");
	}

	configure_sig_handler(fault_handler);

	__asm__ __volatile__ (
#if DEBUG
#warning Using debug payload.
			"\
			debug:                  \n\
			mov %[eax], %%eax       \n\
			mov %[ebx], %%ebx       \n\
			mov %[ecx], %%ecx       \n\
			mov %[edx], %%edx       \n\
			mov %[esi], %%esi       \n\
			mov %[edi], %%edi       \n\
			mov %[ebp], %%ebp       \n\
			mov %[esp], %%esp       \n\
			jmp *%[packet]          \n\
			"
#else
			"\
			debug:                  \n\
			mov %[packet], %%eax    \n\
			mov %[ebx], %%ebx       \n\
			mov %[ecx], %%ecx       \n\
			mov %[edx], %%edx       \n\
			mov %[esi], %%esi       \n\
			mov %[edi], %%edi       \n\
			mov %[ebp], %%ebp       \n\
			mov %[esp], %%esp       \n\
			.byte 0x0f, 0x3f        \n\
			"
#endif // DEBUG
			:
			:
			[eax]"m"(inject_state.eax),
			[ebx]"m"(inject_state.ebx),
			[ecx]"m"(inject_state.ecx),
			[edx]"m"(inject_state.edx),
			[esi]"m"(inject_state.esi),
			[edi]"m"(inject_state.edi),
			[ebp]"m"(inject_state.ebp),
			[esp]"m"(inject_state.esp),
			[packet]"m"(packet)
			);

	__asm__ __volatile__ ("\
			.global resume   \n\
			resume:          \n\
			"
			);
	;
}

void state_handler(int signum, siginfo_t* si, void* p)
{
	fault_context=((ucontext_t*)p)->uc_mcontext;
	((ucontext_t*)p)->uc_mcontext.gregs[REG_EIP]+=UD2_SIZE;
}

void fault_handler(int signum, siginfo_t* si, void* p)
{
	int insn_length;
	ucontext_t* uc=(ucontext_t*)p;

	result=(result_t){
		1,
		signum,
		si->si_code,
		(signum==SIGSEGV||signum==SIGBUS)?(uint32_t)(uintptr_t)si->si_addr:(uint32_t)-1
	};

	memcpy(uc->uc_mcontext.gregs, fault_context.gregs, sizeof(fault_context.gregs));
	uc->uc_mcontext.gregs[REG_EIP]=(uintptr_t)&resume;
	uc->uc_mcontext.gregs[REG_EFL]&=~TF;
}

void configure_sig_handler(void (*handler)(int, siginfo_t*, void*))
{
	struct sigaction s;

	s.sa_sigaction=handler;
	s.sa_flags=SA_SIGINFO|SA_ONSTACK;

	sigfillset(&s.sa_mask);

	sigaction(SIGILL,  &s, NULL);
	sigaction(SIGSEGV, &s, NULL);
	sigaction(SIGFPE,  &s, NULL);
	sigaction(SIGBUS,  &s, NULL);
	sigaction(SIGTRAP, &s, NULL);
}

void generate_instruction(void)
{
	int i, l;

	(*counter)++;
	if ((*counter)%PREFIX_TICK==0) {
		(*prefix)++;
		printf(">> %04x\n", *prefix);
		fflush(stdout);
	}

	for (i=0; i<MAX_INSN_LENGTH; i++) {
		insn.bytes[i]=rand();
	}

	for (i=0; i<PREFIX_LENGTH; i++) {
		insn.bytes[i]=((*prefix)>>(8*(PREFIX_LENGTH-i-1)))&0xff;
	}

	l=get_instruction_length();
	for (i=l; i<MAX_INSN_LENGTH; i++) {
		insn.bytes[i]=0x90;
	}
}

bool is_blacklisted(void)
{
	int i=0;
	while (opcode_blacklist[i].opcode) {
		if (has_opcode((uint8_t*)opcode_blacklist[i].opcode)) {
			return true;
		}
		i++;
	}
	return false;
}

void fuzz(void)
{
	int i;
	void* packet_buffer_unaligned;

	packet_buffer_unaligned=malloc(PAGE_SIZE*2);
	packet=(void*)
		(((uintptr_t)packet_buffer_unaligned+(PAGE_SIZE-1))&~(PAGE_SIZE-1));
	assert(!mprotect(packet,PAGE_SIZE,PROT_READ|PROT_WRITE|PROT_EXEC));

	sigaltstack(&ss, 0);

	while (1) {
		do {
			generate_instruction();
		} while (is_blacklisted());
		if ((*counter&TICK_MASK)==0) {
			printf("%10lld: ", *counter);
			print_insn(&insn);
		}
		inject();
	}

	free(packet_buffer_unaligned);
}

int main(int argc, char** argv)
{
	int i;
	int pid;
	unsigned int seed;

	counter=mmap(NULL, sizeof *counter, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	prefix=mmap(NULL, sizeof *prefix, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	initialize_capstone();

	*counter=0;
	*prefix=START_PREFIX;

	while (1) {
#if GDB
		pid=0;
#else
		pid=fork();
#endif

		if (pid==0) {
			seed=time(NULL)*(*counter+1);
			srand(seed);
			printf("fuzzing (%08x)...\n", seed);
			fflush(stdout);
			fuzz();
		}
		else {
			/* parent */
			uint64_t last_counter=-1;

			while (1) {
				usleep(TIMEOUT);
				if (last_counter==*counter) {
					if (KILL) {
						printf("killing %d\n", pid);
						fflush(stdout);
						kill(pid, SIGKILL);
						break;
					}
					else {
						printf("frozen...\n");
						fflush(stdout);
					}
				}
				else {
					last_counter=*counter;
				}
			}
		}
	}

	return 0;
}
