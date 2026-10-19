#include <windows.h>
#include <stdio.h>
#include "unified.h"

#define UNIFIED_DEVICE_LINK L"\\\\.\\UnifiedDriverLink"
#define MAX_EVENTS 64

typedef struct _MONITOR_EVENT {
    BOOLEAN IsCreate;
    ULONG Pid;
    ULONG ParentPid;
    WCHAR ImageName[128];
} MONITOR_EVENT;

static HANDLE OpenDevice(void)
{
    HANDLE h = CreateFileW(UNIFIED_DEVICE_LINK,
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        printf("[-] CreateFileW echoue err=%lu\n", GetLastError());
    return h;
}

static int DoProtect(DWORD pid)
{
    HANDLE h = OpenDevice();
    DWORD bytesReturned = 0;
    BOOL ok;

    if (h == INVALID_HANDLE_VALUE)
        return 1;

    ok = DeviceIoControl(h, IOCTL_SET_PROTECTED_PID,
                         &pid, sizeof(pid),
                         NULL, 0, &bytesReturned, NULL);
    if (!ok)
        printf("[-] IOCTL_SET_PROTECTED_PID echoue err=%lu\n", GetLastError());
    else
        printf("[+] PID %lu protege\n", pid);

    CloseHandle(h);
    return ok ? 0 : 1;
}

static int DoEvents(void)
{
    HANDLE h = OpenDevice();
    MONITOR_EVENT events[MAX_EVENTS];
    DWORD bytesReturned = 0;
    BOOL ok;
    DWORD count, i;

   if (h == INVALID_HANDLE_VALUE)
        return 1;

    ZeroMemory(events, sizeof(events));
    ok = DeviceIoControl(h, IOCTL_GET_EVENTS,
                         NULL, 0,
                         events, sizeof(events),
                         &bytesReturned, NULL);
    if (!ok) {
        printf("[-] IOCTL_GET_EVENTS echoue err=%lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    count = bytesReturned / sizeof(MONITOR_EVENT);
    printf("[+] %lu evenements\n", count);
    for (i = 0; i < count; i++) {
        if (events[i].IsCreate)
            wprintf(L"  [CREATE] PID=%lu PPID=%lu Image=%s\n",
                    events[i].Pid, events[i].ParentPid, events[i].ImageName);
        else
            printf("  [EXIT]   PID=%lu\n", events[i].Pid);
    }

    CloseHandle(h);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s protect <pid>\n", argv[0]);
        printf("  %s events\n", argv[0]);
        return 1;
    }
    if (_stricmp(argv[1], "protect") == 0) {
        if (argc < 3) { printf("Usage: %s protect <pid>\n", argv[0]); return 1; }
        return DoProtect((DWORD)atoi(argv[2]));
    }
    if (_stricmp(argv[1], "events") == 0)
        return DoEvents();
    printf("commande inconnue\n");
    return 1;
}
