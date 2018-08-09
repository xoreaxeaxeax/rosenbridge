#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/timer.h>

#define DEVICE_NAME "watch_mem"

int g_time_interval = 1000;
struct timer_list g_timer;

unsigned char buffer[]={
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};

void tick(unsigned long data)
{
	printk(">>> &buffer: %08lx > %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			(uintptr_t)buffer,
			buffer[0],
			buffer[1],
			buffer[2],
			buffer[3],
			buffer[4],
			buffer[5],
			buffer[6],
			buffer[7],
			buffer[8],
			buffer[9],
			buffer[10],
			buffer[11],
			buffer[12],
			buffer[13],
			buffer[14],
			buffer[15]
		  );

	/* restart the timer */
	mod_timer(&g_timer, jiffies+msecs_to_jiffies(g_time_interval));
}

static int __init watch_init(void)
{
	printk(KERN_INFO "entering\n");

	/* start the timer */
	setup_timer(&g_timer, tick, 0);
	mod_timer( &g_timer, jiffies + msecs_to_jiffies(g_time_interval));

	return 0;
}

static void __exit watch_cleanup(void)
{
	printk(KERN_INFO "Cleaning up module.\n");
	del_timer(&g_timer);
}

module_init(watch_init);
module_exit(watch_cleanup);
