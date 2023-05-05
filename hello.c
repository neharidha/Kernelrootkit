#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL v2");

MODULE_AUTHOR("NEHA");
MODULE_DESCRIPTION("LKM ROOTKIT");
MODULE_VERSION("0.0.1");


static int __init mod_init(void)
{
        printk(KERN_INFO "rootkit: init\n");
        
        return 0;

}
static void __exit mod_exit(void)
{
        printk(KERN_INFO "rootkit:exit\n");
}

module_init(mod_init);
module_exit(mod_exit);
