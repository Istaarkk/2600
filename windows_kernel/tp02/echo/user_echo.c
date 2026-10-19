#include <windows.h>
#include <stdio.h>
#include "echo.h"

#define ECHO_DEVICE_LINK L"\\\\.\\EchoDriverLink"

int main(int argc, char *argv[])
{
    HANDLE hDevice;
    char inputBuffer[ECHO_MAX_BUFFER_SIZE];
    char outputBuffer[ECHO_MAX_BUFFER_SIZE];
    DWORD bytesReturned = 0;
    size_t len;
    BOOL ok;

    if (argc < 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }

   len = strlen(argv[1]);
    if (len >= ECHO_MAX_BUFFER_SIZE) {
        printf("[-] trop long\n");
        return 1;
    }

    ZeroMemory(inputBuffer, sizeof(inputBuffer));
    ZeroMemory(outputBuffer, sizeof(outputBuffer));
    memcpy(inputBuffer, argv[1], len);

    hDevice = CreateFileW(ECHO_DEVICE_LINK, GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] ouverture device echouee err=%lu\n", GetLastError());
        return 1;
    }

    printf("[*] envoi : \"%s\"\n", argv[1]);

    ok = DeviceIoControl(hDevice, IOCTL_ECHO,
                         inputBuffer, (DWORD)len,
                         outputBuffer, (DWORD)sizeof(outputBuffer),
                         &bytesReturned, NULL);
    if (!ok) {
        printf("[-] DeviceIoControl echoue err=%lu\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] reponse (%lu octets) : \"%.*s\"\n",
           bytesReturned, (int)bytesReturned, outputBuffer);

    CloseHandle(hDevice);
    return 0;
}
