#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_BUFFER_SIZE 4096
#define IOCTL_TIMEOUT_MS 2000

DWORD generate_ioctl_code(DWORD function, DWORD method)
{
    return CTL_CODE(FILE_DEVICE_UNKNOWN, function, method, FILE_ANY_ACCESS);
}

void generate_random_buffer(PUCHAR buffer, DWORD size)
{
   DWORD i;
    for (i = 0; i < size; i++) {
        buffer[i] = (UCHAR)(rand() % 256);
    }
}

typedef struct _IOCTL_CALL_CTX {
    HANDLE hDevice;
    DWORD  ioctlCode;
    PVOID  inBuffer;
    DWORD  inSize;
    PVOID  outBuffer;
    DWORD  outSize;
    DWORD  bytesReturned;
    BOOL   result;
    DWORD  lastError;
} IOCTL_CALL_CTX;

DWORD WINAPI IoctlThreadProc(LPVOID param)
{
    IOCTL_CALL_CTX *ctx = (IOCTL_CALL_CTX *)param;
    ctx->result = DeviceIoControl(ctx->hDevice, ctx->ioctlCode,
                                  ctx->inBuffer, ctx->inSize,
                                  ctx->outBuffer, ctx->outSize,
                                  &ctx->bytesReturned, NULL);
    if (!ctx->result)
        ctx->lastError = GetLastError();
    return 0;
}

BOOL SendIoctlWithTimeout(IOCTL_CALL_CTX *ctx, DWORD timeoutMs, BOOL *timedOut)
{
    HANDLE hThread;
    DWORD waitResult;

    *timedOut = FALSE;
    hThread = CreateThread(NULL, 0, IoctlThreadProc, ctx, 0, NULL);
    if (hThread == NULL) {
        ctx->result = FALSE;
        ctx->lastError = GetLastError();
        return FALSE;
    }

    waitResult = WaitForSingleObject(hThread, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        *timedOut = TRUE;
        CloseHandle(hThread);
        return FALSE;
    }
    CloseHandle(hThread);
    return ctx->result;
}

int main(int argc, char *argv[])
{
    char *devicePathA;
    wchar_t devicePathW[MAX_PATH];
    HANDLE hDevice;
    int iterations;
    int i;
    UCHAR inBuffer[MAX_BUFFER_SIZE];
    UCHAR outBuffer[MAX_BUFFER_SIZE];
    int successCount = 0;
    int errorCount = 0;
    int timeoutCount = 0;
    DWORD uniqueErrors[64];
    int uniqueErrorCounts[64];
    int uniqueErrorN = 0;

    if (argc < 2) {
        printf("Usage: %s <device_path> [iterations]\n", argv[0]);
        return 1;
    }

   devicePathA = argv[1];
   iterations = (argc > 2) ? atoi(argv[2]) : 100;
    srand((unsigned int)time(NULL));

    if (MultiByteToWideChar(CP_ACP, 0, devicePathA, -1, devicePathW, MAX_PATH) == 0) {
        printf("[-] conversion echouee\n");
        return 1;
    }

    hDevice = CreateFileW(devicePathW, GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[-] CreateFileW echoue err=%lu\n", err);
        if (err == ERROR_FILE_NOT_FOUND)
            printf("[-] device inexistant\n");
        return 1;
    }

    printf("[+] %s ouvert, fuzzing %d iterations\n\n", devicePathA, iterations);

    for (i = 0; i < iterations; i++) {
        DWORD function = (DWORD)(rand() % 0x1000);
        DWORD method   = (DWORD)(rand() % 4);
        DWORD ioctlCode = generate_ioctl_code(function, method);
        DWORD inSize  = (DWORD)(rand() % (MAX_BUFFER_SIZE + 1));
        DWORD outSize = (DWORD)(rand() % (MAX_BUFFER_SIZE + 1));
        IOCTL_CALL_CTX ctx;
        BOOL timedOut = FALSE;
        BOOL ok;

        generate_random_buffer(inBuffer, inSize);
        ZeroMemory(outBuffer, sizeof(outBuffer));
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.hDevice   = hDevice;
        ctx.ioctlCode = ioctlCode;
        ctx.inBuffer  = inBuffer;
        ctx.inSize    = inSize;
        ctx.outBuffer = outBuffer;
        ctx.outSize   = outSize;

        ok = SendIoctlWithTimeout(&ctx, IOCTL_TIMEOUT_MS, &timedOut);

        if (timedOut) {
            timeoutCount++;
            printf("[%4d] IOCTL=0x%08lX -> TIMEOUT\n", i, ioctlCode);
            continue;
        }

        if (ok) {
            successCount++;
            printf("[%4d] IOCTL=0x%08lX inSize=%lu -> SUCCESS bytes=%lu\n",
                   i, ioctlCode, inSize, ctx.bytesReturned);
        } else {
            errorCount++;
            printf("[%4d] IOCTL=0x%08lX inSize=%lu -> ERROR err=%lu\n",
                   i, ioctlCode, inSize, ctx.lastError);
            {
                int found = 0, j;
                for (j = 0; j < uniqueErrorN; j++) {
                    if (uniqueErrors[j] == ctx.lastError) {
                        uniqueErrorCounts[j]++;
                        found = 1;
                        break;
                    }
                }
                if (!found && uniqueErrorN < 64) {
                    uniqueErrors[uniqueErrorN] = ctx.lastError;
                    uniqueErrorCounts[uniqueErrorN] = 1;
                    uniqueErrorN++;
                }
            }
        }
    }

    CloseHandle(hDevice);
    printf("\n--- Stats ---\n");
    printf("Succes : %d  Erreurs : %d  Timeouts : %d\n",
           successCount, errorCount, timeoutCount);
    for (i = 0; i < uniqueErrorN; i++)
        printf("  err=%lu : %d fois\n", uniqueErrors[i], uniqueErrorCounts[i]);
    return 0;
}
