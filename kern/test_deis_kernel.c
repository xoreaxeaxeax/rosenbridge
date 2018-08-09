#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include "deis_kernel.h"

int main(void)
{
	int i;
	uintptr_t buffer_address;
	unsigned int buffer_size;
	unsigned char* buffer=NULL;
	int handle;

	handle=open("/dev/deis_kernel", O_RDWR);

	if (!handle) {
		printf("could not open device\n");
		exit(-1);
	}

	ioctl(handle, GET_BUFFER_SIZE, &buffer_size);
	printf("buffer size: %d\n", buffer_size);
	buffer=malloc(buffer_size);

	ioctl(handle, GET_BUFFER_ADDRESS, &buffer_address);
	printf("buffer address: %08x\n", buffer_address);

	ioctl(handle, READ_BUFFER, buffer);
	for (i=0; i<buffer_size; i++) {
		printf("%02x ", buffer[i]);
	}
	printf("\n");

	/*
	ioctl(handle, RESET_BUFFER, NULL);

	ioctl(handle, READ_BUFFER, buffer);
	for (i=0; i<buffer_size; i++) {
		printf("%02x ", buffer[i]);
	}
	printf("\n");
	*/

	close(handle);

	return 0;
}
