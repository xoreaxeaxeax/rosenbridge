#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/device.h>

#include "privregs.h"

#define DEBUG 1

#define USE_AMD_PASSWORD 1
#define AMD_PASSWORD_VAL "0x9c5a203a"
#define AMD_PASSWORD_REG "esi"

#if DEBUG
	#define msg(m, ...) { printk(KERN_INFO "(%s)>> " m, device_name, ##__VA_ARGS__); }
#else
	#define msg(m, ...)
#endif

#if defined(__x86_64__)
typedef struct __attribute__ ((packed)) { uint64_t lo; uint64_t hi; } idt_descriptor_t;
typedef struct __attribute__ ((packed)) { uint16_t size; uint64_t base; } idtr_t;
typedef uint64_t register_t;
#define PRIxPTR "016lx"
#define FAULT_BYTES "32"
#define SP "rsp"
#elif defined(__i386__)
typedef struct __attribute__ ((packed)) { uint64_t lo; } idt_descriptor_t; 
typedef struct __attribute__ ((packed)) { uint16_t size; uint32_t base; } idtr_t;
typedef uint32_t register_t;
#define PRIxPTR "08lx"
#define FAULT_BYTES "16"
#define SP "esp"
#else
	#error
#endif

#define IDT_ALIGN     4096
#define IDT_ENTRIES   256

static void* idt_buffer=NULL;
static void* idt=NULL;
static idtr_t idtr_old, idtr_new;

static const char device_name[]="privregs";

static dev_t privregs_devno;
static struct cdev privregs_cdev;
static struct class *privregs_class;

static long privreg_ioctl(
	struct file* file,
	unsigned int cmd,
	unsigned long val
	);

static const struct file_operations fops={
	.owner = THIS_MODULE,
	.unlocked_ioctl = privreg_ioctl
};

static long privreg_ioctl(
	struct file* file,
	unsigned int usr_cmd,
	unsigned long usr_val
	)
{
	unsigned int cmd;
	privregs_req_t req;
	register unsigned long r_data;

	cmd = usr_cmd;
	get_user(req.reg, &((privregs_req_t*)usr_val)->reg);
	/* get_user(req.val, &((privregs_req_t*)usr_val)->val); */
	/* poor old kernel can't find this? ^ */
	copy_from_user(&req.val, &((privregs_req_t*)usr_val)->val, sizeof(req.val));

	msg("ioctl %08x %08x %08llx\n", cmd, req.reg, req.val);

	switch (cmd) {
		case READ_CR:
			r_data=0;
			msg("cr read %u\n", req.reg);
			switch (req.reg) {
				case 0: __asm__ __volatile__ ("mov %%cr0, %0" : "=r"(r_data)); break;
				case 1: __asm__ __volatile__ ("mov %%cr1, %0" : "=r"(r_data)); break;
				case 2: __asm__ __volatile__ ("mov %%cr2, %0" : "=r"(r_data)); break;
				case 3: __asm__ __volatile__ ("mov %%cr3, %0" : "=r"(r_data)); break;
				case 4: __asm__ __volatile__ ("mov %%cr4, %0" : "=r"(r_data)); break;
				case 5: __asm__ __volatile__ ("mov %%cr5, %0" : "=r"(r_data)); break;
				case 6: __asm__ __volatile__ ("mov %%cr6, %0" : "=r"(r_data)); break;
				case 7: __asm__ __volatile__ ("mov %%cr7, %0" : "=r"(r_data)); break;
				case 8: __asm__ __volatile__ ("mov %%cr8, %0" : "=r"(r_data)); break;
				case 9: __asm__ __volatile__ ("mov %%cr9, %0" : "=r"(r_data)); break;
				case 10: __asm__ __volatile__ ("mov %%cr10, %0" : "=r"(r_data)); break;
				case 11: __asm__ __volatile__ ("mov %%cr11, %0" : "=r"(r_data)); break;
				case 12: __asm__ __volatile__ ("mov %%cr12, %0" : "=r"(r_data)); break;
				case 13: __asm__ __volatile__ ("mov %%cr13, %0" : "=r"(r_data)); break;
				case 14: __asm__ __volatile__ ("mov %%cr14, %0" : "=r"(r_data)); break;
				case 15: __asm__ __volatile__ ("mov %%cr15, %0" : "=r"(r_data)); break;
				default:
					msg("unsupported cr read %u\n", req.reg);
					break;
			}
			req.val=r_data;
			break;
		case WRITE_CR:
			r_data=req.val;
			msg("cr write %u\n", req.reg);
			switch (req.reg) {
				case 0: __asm__ __volatile__ ("mov %0, %%cr0" : : "r"(r_data)); break;
				case 1: __asm__ __volatile__ ("mov %0, %%cr1" : : "r"(r_data)); break;
				case 2: __asm__ __volatile__ ("mov %0, %%cr2" : : "r"(r_data)); break;
				case 3: __asm__ __volatile__ ("mov %0, %%cr3" : : "r"(r_data)); break;
				case 4: __asm__ __volatile__ ("mov %0, %%cr4" : : "r"(r_data)); break;
				case 5: __asm__ __volatile__ ("mov %0, %%cr5" : : "r"(r_data)); break;
				case 6: __asm__ __volatile__ ("mov %0, %%cr6" : : "r"(r_data)); break;
				case 7: __asm__ __volatile__ ("mov %0, %%cr7" : : "r"(r_data)); break;
				case 8: __asm__ __volatile__ ("mov %0, %%cr8" : : "r"(r_data)); break;
				case 9: __asm__ __volatile__ ("mov %0, %%cr9" : : "r"(r_data)); break;
				case 10: __asm__ __volatile__ ("mov %0, %%cr10" : : "r"(r_data)); break;
				case 11: __asm__ __volatile__ ("mov %0, %%cr11" : : "r"(r_data)); break;
				case 12: __asm__ __volatile__ ("mov %0, %%cr12" : : "r"(r_data)); break;
				case 13: __asm__ __volatile__ ("mov %0, %%cr13" : : "r"(r_data)); break;
				case 14: __asm__ __volatile__ ("mov %0, %%cr14" : : "r"(r_data)); break;
				case 15: __asm__ __volatile__ ("mov %0, %%cr15" : : "r"(r_data)); break;
				default:
					msg("unsupported cr write %u\n", req.reg);
					break;
			}
			break;
		case READ_DR:
			r_data=0;
			msg("dr read %u\n", req.reg);
			switch (req.reg) {
				case 0: __asm__ __volatile__ ("mov %%dr0, %0" : "=r"(r_data)); break;
				case 1: __asm__ __volatile__ ("mov %%dr1, %0" : "=r"(r_data)); break;
				case 2: __asm__ __volatile__ ("mov %%dr2, %0" : "=r"(r_data)); break;
				case 3: __asm__ __volatile__ ("mov %%dr3, %0" : "=r"(r_data)); break;
				case 4: __asm__ __volatile__ ("mov %%dr4, %0" : "=r"(r_data)); break;
				case 5: __asm__ __volatile__ ("mov %%dr5, %0" : "=r"(r_data)); break;
				case 6: __asm__ __volatile__ ("mov %%dr6, %0" : "=r"(r_data)); break;
				case 7: __asm__ __volatile__ ("mov %%dr7, %0" : "=r"(r_data)); break;
				default:
					msg("unsupported dr read %u\n", req.reg);
					break;
			}
			req.val=r_data;
			break;
		case WRITE_DR:
			r_data=req.val;
			msg("dr write %u\n", req.reg);
			switch (req.reg) {
				case 0: __asm__ __volatile__ ("mov %0, %%dr0" : : "r"(r_data)); break;
				case 1: __asm__ __volatile__ ("mov %0, %%dr1" : : "r"(r_data)); break;
				case 2: __asm__ __volatile__ ("mov %0, %%dr2" : : "r"(r_data)); break;
				case 3: __asm__ __volatile__ ("mov %0, %%dr3" : : "r"(r_data)); break;
				case 4: __asm__ __volatile__ ("mov %0, %%dr4" : : "r"(r_data)); break;
				case 5: __asm__ __volatile__ ("mov %0, %%dr5" : : "r"(r_data)); break;
				case 6: __asm__ __volatile__ ("mov %0, %%dr6" : : "r"(r_data)); break;
				case 7: __asm__ __volatile__ ("mov %0, %%dr7" : : "r"(r_data)); break;
				default:
					msg("unsupported dr write %u\n", req.reg);
					break;
			}
			break;
		case READ_MSR:
			__asm__ __volatile__ ("\
					movl %2, %%ecx \n\
					rdmsr          \n\
					movl %%eax, %0 \n\
					movl %%edx, %1 \n\
					"
					:"=m"(req.val), "=m"(*((uint32_t*)&req.val+1))
					:"m"(req.reg)
					:"eax", "ecx", "edx"
					);
			break;
		case WRITE_MSR:
			__asm__ __volatile__ ("\
					"
#if USE_AMD_PASSWORD
					"\
					movl $" AMD_PASSWORD_VAL ", %%" AMD_PASSWORD_REG "\n\
					"
#endif
					"\
					movl %2, %%ecx \n\
					movl %0, %%eax \n\
					movl %1, %%edx \n\
					wrmsr          \n\
					"
					:
					:"m"(req.val), "m"(*((uint32_t*)&req.val+1)), "m"(req.reg)
					:"eax", "ecx", "edx", AMD_PASSWORD_REG
					);
			break;
		case CHECK_MSR:
			__asm__ __volatile__ ("lidt %0" :: "m"(idtr_new));
			__asm__ __volatile__ ("\
					"
#if USE_AMD_PASSWORD
					"\
					movl $" AMD_PASSWORD_VAL ", %%" AMD_PASSWORD_REG "\n\
					"
#endif
					"\
					movl %1, %%ecx \n\
					rdmsr          \n\
					movl $1, %0    \n\
					jmp done       \n\
					handler:       \n\
					add $" FAULT_BYTES ", %%" SP "\n\
					movl $0, %0    \n\
					done:          \n\
					"
					:"=m"(req.val)
					:"m"(req.reg)
					:"eax", "ecx", "edx", AMD_PASSWORD_REG
					);
			__asm__ __volatile__ ("lidt %0" :: "m"(idtr_old));
			break;
		case READ_SEG:
			r_data=0;
			msg("seg read %u\n", req.reg);
			switch (req.reg) {
				case SEG_DS: __asm__ __volatile__ ("mov %%ds, %0" : "=r"(r_data)); break;
				case SEG_ES: __asm__ __volatile__ ("mov %%es, %0" : "=r"(r_data)); break;
				case SEG_FS: __asm__ __volatile__ ("mov %%fs, %0" : "=r"(r_data)); break;
				case SEG_GS: __asm__ __volatile__ ("mov %%gs, %0" : "=r"(r_data)); break;
				case SEG_SS: __asm__ __volatile__ ("mov %%ss, %0" : "=r"(r_data)); break;
				case SEG_CS: __asm__ __volatile__ ("mov %%cs, %0" : "=r"(r_data)); break;
				default:
					msg("unsupported seg read %u\n", req.reg);
					break;
			}
			req.val=r_data;
			break;
		case WRITE_SEG:
			r_data=req.val;
			msg("seg write %u\n", req.reg);
			switch (req.reg) {
				case SEG_DS: __asm__ __volatile__ ("mov %0, %%ds" : : "r"(r_data)); break;
				case SEG_ES: __asm__ __volatile__ ("mov %0, %%es" : : "r"(r_data)); break;
				case SEG_FS: __asm__ __volatile__ ("mov %0, %%fs" : : "r"(r_data)); break;
				case SEG_GS: __asm__ __volatile__ ("mov %0, %%gs" : : "r"(r_data)); break;
				case SEG_SS: __asm__ __volatile__ ("mov %0, %%ss" : : "r"(r_data)); break;
				case SEG_CS: __asm__ __volatile__ ("mov %0, %%cs" : : "r"(r_data)); break;
				default:
					msg("unsupported seg write %u\n", req.reg);
					break;
			}
			break;
		default:
			msg("unrecognized ioctl %d\n", cmd);
			break;
	}
	put_user(req.reg, &((privregs_req_t*)usr_val)->reg);
	put_user(req.val, &((privregs_req_t*)usr_val)->val);
	return 0;
}

static int swap_idt(void)
{
	extern /* void */ char handler;
	uint64_t fault_handler=(uint64_t)(uintptr_t)&handler;
	idt_descriptor_t descriptor_d_catch, descriptor_d_orig;

	msg("swapping idt\n");

	idt_buffer=kmalloc(IDT_ALIGN+IDT_ENTRIES*sizeof(idt_descriptor_t), GFP_KERNEL);
	if (idt_buffer==NULL) { return -1; }
	idt=(void*)(((uintptr_t)idt_buffer)&~((uintptr_t)IDT_ALIGN-1));

	msg("idt_buffer: %"PRIxPTR"\n", (uintptr_t)idt_buffer);
	msg("idt:        %"PRIxPTR"\n", (uintptr_t)idt);

	__asm__ __volatile__ ("\
			sidt %[_idt]     \n\
			"
			: [_idt]"=m"(idtr_old)
			);

	msg("idtr.base: %"PRIxPTR"\n", (uintptr_t)idtr_old.base);
	msg("idtr.size: %04x\n", idtr_old.size);

	descriptor_d_orig=((idt_descriptor_t*)idtr_old.base)[0xd];

	msg("idt[d].lo: %016llx\n", descriptor_d_orig.lo);

	memcpy(idt, (void*)idtr_old.base, IDT_ENTRIES*sizeof(idt_descriptor_t));

	idtr_new.size=idtr_old.size;
	idtr_new.base=(uintptr_t)idt;

	msg("handler address > %"PRIxPTR"\n", (uintptr_t)&handler);

	descriptor_d_catch.lo=
		(descriptor_d_orig.lo&0x0000ffffffff0000ULL)|
		(fault_handler&0x000000000000ffffULL) |
		((fault_handler&0x00000000ffff0000ULL) << 32);

	#if defined(__x86_64__)
	descriptor_d_catch.hi=
		((fault_handler&0xffffffff00000000ULL) >> 32);
	#endif

	((idt_descriptor_t*)idtr_new.base)[0xd]=descriptor_d_catch;

	msg("idt[d].lo: %016llx\n", descriptor_d_catch.lo);

	return 0;
}

static void unswap_idt(void)
{
	kfree(idt_buffer);
}

static char *privregs_devnode(struct device *dev, umode_t *mode)
{
	if (!mode)
		return NULL;
	/*
	if (dev->devt == MKDEV(TTYAUX_MAJOR, 0) ||
				dev->devt == MKDEV(TTYAUX_MAJOR, 2))
	*/
	*mode=0666;
	return NULL;
}

static int register_device(void)
{
	int result;
	struct device *dev_ret;

	if ((result=alloc_chrdev_region(&privregs_devno, 0, 1, device_name)) < 0) {
		return result;
	}

	if (IS_ERR(privregs_class=class_create(THIS_MODULE, device_name))) {
		unregister_chrdev_region(privregs_devno, 1);
		return PTR_ERR(privregs_class);
	}
	privregs_class->devnode=privregs_devnode;
	if (IS_ERR(dev_ret=device_create(privregs_class, NULL, privregs_devno, NULL, device_name))) {
		class_destroy(privregs_class);
		unregister_chrdev_region(privregs_devno, 1);
		return PTR_ERR(dev_ret);
	}

	cdev_init(&privregs_cdev, &fops);
	if ((result = cdev_add(&privregs_cdev, privregs_devno, 1)) < 0)
	{
		device_destroy(privregs_class, privregs_devno);
		class_destroy(privregs_class);
		unregister_chrdev_region(privregs_devno, 1);
		return result;
	}

	return 0;
}

static void unregister_device(void)
{
	msg("unregister\n");
	cdev_del(&privregs_cdev);
	device_destroy(privregs_class, privregs_devno);
	class_destroy(privregs_class);
	unregister_chrdev_region(privregs_devno, 1);
}

static int __init init_privreg(void)
{
	int result;
	msg("init\n");
	result=register_device();

	if (!result) {
		result=swap_idt();
	}

	return result;
}

static void __exit cleanup_privreg(void)
{
	msg("exit\n");
	unswap_idt();
	unregister_device();
}

module_init(init_privreg);
module_exit(cleanup_privreg);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xoreaxeaxeax");
MODULE_DESCRIPTION("Access to ring 0 registers");
