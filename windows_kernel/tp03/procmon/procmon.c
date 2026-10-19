#include <ntddk.h>

VOID ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        ULONG ppid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        DbgPrint("ProcMon: [CREATE] PID=%lu PPID=%lu Image=%wZ CmdLine=%wZ\n",
                 pid, ppid, CreateInfo->ImageFileName, CreateInfo->CommandLine);
    } else {
        DbgPrint("ProcMon: [EXIT] PID=%lu\n", pid);
    }
}

VOID ProcMonUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DriverObject);
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    if (!NT_SUCCESS(status))
        DbgPrint("ProcMon: desenregistrement echoue 0x%08X\n", status);
    DbgPrint("ProcMon: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcMon: enregistrement echoue 0x%08X (integritycheck ?)\n", status);
        return status;
    }

    DriverObject->DriverUnload = ProcMonUnload;
    DbgPrint("ProcMon: loaded\n");
    return STATUS_SUCCESS;
}
