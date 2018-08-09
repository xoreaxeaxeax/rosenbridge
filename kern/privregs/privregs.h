#ifndef PRIVREGS_H
#define PRIVREGS_H

#define READ_CR    0x8001
#define READ_DR    0x8002
#define READ_SEG   0x8003
#define READ_MSR   0x8004
#define WRITE_CR   0x8005
#define WRITE_DR   0x8006
#define WRITE_SEG  0x8007
#define WRITE_MSR  0x8008
#define CHECK_MSR  0x8009

typedef enum {
	SEG_DS,
	SEG_ES,
	SEG_FS,
	SEG_GS,
	SEG_SS,
	SEG_CS
} segment_register_t;

typedef struct {
	uint32_t reg;
	uint64_t val;
} privregs_req_t;

#endif // PRIVREGS_H
