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

#include "deis_kernel.h"

#define DEBUG 0

#if DEBUG
	#define msg(m, ...) { printk(KERN_INFO "(%s)>> " m, device_name, ##__VA_ARGS__); }
#else
	#define msg(m, ...)
#endif

#define BUFFER_SIZE 32
unsigned char buffer[BUFFER_SIZE];

static const char device_name[]="deis_kernel";

static dev_t deis_kernel_devno;
static struct cdev deis_kernel_cdev;
static struct class *deis_kernel_class;

static long deis_kernel_ioctl(
	struct file* file,
	unsigned int cmd,
	unsigned long val
	);

static const struct file_operations fops={
	.owner = THIS_MODULE,
	.unlocked_ioctl = deis_kernel_ioctl
};

static void reset_buffer(void)
{
	int i;
	for (i=0; i<BUFFER_SIZE; i++) {
		buffer[i]=(0x11*i)&0xff;
	}
}

static long deis_kernel_ioctl(
	struct file* file,
	unsigned int cmd,
	unsigned long val
	)
{
	msg("ioctl %08x %08lx\n", cmd, val);

	switch (cmd) {
		case GET_BUFFER_ADDRESS:
			msg("get_buffer_address\n");
			put_user((uintptr_t)&buffer, (uintptr_t*)val);
			break;
		case GET_BUFFER_SIZE:
			msg("get_buffer_size\n");
			put_user(BUFFER_SIZE, (unsigned int*)val);
			break;
		case READ_BUFFER:
			msg("read_buffer\n");
			copy_to_user((void*)val, buffer, BUFFER_SIZE);
			break;
		case RESET_BUFFER:
			msg("reset_buffer\n");
			reset_buffer();
			break;
		default:
			msg("unrecognized ioctl %d\n", cmd);
			break;
	}
	return 0;
}

static char *deis_kernel_devnode(struct device *dev, umode_t *mode)
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

	reset_buffer();

	if ((result=alloc_chrdev_region(&deis_kernel_devno, 0, 1, device_name)) < 0) {
		return result;
	}

	if (IS_ERR(deis_kernel_class=class_create(THIS_MODULE, device_name))) {
		unregister_chrdev_region(deis_kernel_devno, 1);
		return PTR_ERR(deis_kernel_class);
	}
	deis_kernel_class->devnode=deis_kernel_devnode;
	if (IS_ERR(dev_ret=device_create(deis_kernel_class, NULL, deis_kernel_devno, NULL, device_name))) {
		class_destroy(deis_kernel_class);
		unregister_chrdev_region(deis_kernel_devno, 1);
		return PTR_ERR(dev_ret);
	}

	cdev_init(&deis_kernel_cdev, &fops);
	if ((result = cdev_add(&deis_kernel_cdev, deis_kernel_devno, 1)) < 0)
	{
		device_destroy(deis_kernel_class, deis_kernel_devno);
		class_destroy(deis_kernel_class);
		unregister_chrdev_region(deis_kernel_devno, 1);
		return result;
	}

	return 0;
}

static void unregister_device(void)
{
	msg("unregister\n");
	cdev_del(&deis_kernel_cdev);
	device_destroy(deis_kernel_class, deis_kernel_devno);
	class_destroy(deis_kernel_class);
	unregister_chrdev_region(deis_kernel_devno, 1);
}

static int __init init_deis_kernel(void)
{
	int result;
	msg("init\n");
	result=register_device();
	return result;
}

static void __exit cleanup_deis_kernel(void)
{
	msg("exit\n");
	unregister_device();
}

module_init(init_deis_kernel);
module_exit(cleanup_deis_kernel);

MODULE_LICENSE("GPL");

