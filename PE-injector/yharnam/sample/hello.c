#include <windows.h>
#include <stdio.h>

int     main(int ac, char **av)
{
  for (int i = 0; i < ac; i += 1)
  {
    printf("ARG %d : %s\n", i, av[i]);
  }

  HANDLE    hFile;
  DWORD dwBytesWritten = 0;
  unsigned char outBuffer[] = "Hello World !!!";

  hFile = CreateFile("hello.txt", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                     0, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("CreateFile()... ERROR\n");
    return (-1);
  }
  printf("CreateFile()... SUCCESS\n");

  if ((WriteFile(
           hFile,               // HANDLE       hFile
           outBuffer,           // LPCVOID      lpBuffer,
           sizeof (outBuffer),  // DWORD        nNumberOfBytesToWrite
           &dwBytesWritten,     // LPDWORD      lpNumberOfBytesWritten,
           NULL                 // LPOVERLAPPED lpOverlapped
         )) == 0) {
    printf("WriteFile()... ERROR\n");
    return (-1);
  }

  printf("WriteFile()... SUCCESS\n");

  if ((CloseHandle(hFile)) == 0) {
    printf("CloseHandle()... ERROR\n");
    return (-1);
  }
  printf("CloseHandle()... SUCCESS\n");

  return (0);
}
