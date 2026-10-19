#ifndef HIDE_FILE_H
#define HIDE_FILE_H

#include <linux/types.h>

int  hide_file_init(void);
void hide_file_exit(void);
void set_hidden_pid(pid_t pid);
void set_hidden_file(const char *name);
void clear_hidden_file(void);

#endif
