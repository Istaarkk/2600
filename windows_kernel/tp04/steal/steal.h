#ifndef STEAL_H
#define STEAL_H

#ifndef _NTDDK_
#include <winioctl.h>
#endif

#define IOCTL_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
