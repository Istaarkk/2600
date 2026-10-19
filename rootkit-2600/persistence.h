#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#define INITTAB_PATH    "/etc/inittab"
#define CRONTAB_PATH    "/etc/crontabs/root"

int  persistence_init(void);
void persistence_exit(void);

#endif
