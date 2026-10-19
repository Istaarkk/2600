#ifndef ECHO_H
#define ECHO_H

#ifndef _NTDDK_
#include <winioctl.h>
#endif

#define IOCTL_ECHO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ECHO_MAX_BUFFER_SIZE 4096

#endif
