#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define IOCTL_SET_PROTECTED_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB00, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, char *argv[])
{
    HANDLE hDevice;
    DWORD pid;
    DWORD bytesReturned;
    BOOL ok;

    if (argc != 2) {
        printf("Usage: protector_ctl.exe <pid>\n");
        return 1;
    }

    pid = (DWORD)atoi(argv[1]);

    hDevice = CreateFileW(L"\\\\.\\ProtectorDriverLink",
                          GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Erreur ouverture driver: %lu\n", GetLastError());
        return 1;
    }

    ok = DeviceIoControl(hDevice, IOCTL_SET_PROTECTED_PID,
                         &pid, sizeof(pid),
                         NULL, 0,
                         &bytesReturned, NULL);
    if (!ok)
        printf("IOCTL echoue: %lu\n", GetLastError());
    else
        printf("PID %lu protege\n", pid);

    CloseHandle(hDevice);
    return ok ? 0 : 1;
}
