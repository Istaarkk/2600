#include <ntddk.h>
#include "unified.h"

#define DEVICE_NAME  L"\\Device\\UnifiedDriver"
#define SYMLINK_NAME L"\\??\\UnifiedDriverLink"
#define MAX_EVENTS 64

typedef struct _MONITOR_EVENT {
    BOOLEAN IsCreate;
    ULONG Pid;
    ULONG ParentPid;
    WCHAR ImageName[128];
} MONITOR_EVENT;

volatile LONG gProtectedPid = 0;
MONITOR_EVENT gEvents[MAX_EVENTS];
ULONG gEventCount = 0;
ULONG gEventWriteIndex = 0;
KSPIN_LOCK gEventsLock;
PVOID gObRegistrationHandle = NULL;

VOID LogEvent(_In_ BOOLEAN IsCreate, _In_ ULONG Pid, _In_ ULONG ParentPid,
              _In_opt_ PUNICODE_STRING ImageFileName)
{
    KIRQL oldIrql;
    PMONITOR_EVENT ev;

   KeAcquireSpinLock(&gEventsLock, &oldIrql);
    ev = &gEvents[gEventWriteIndex];
    ev->IsCreate  = IsCreate;
    ev->Pid       = Pid;
    ev->ParentPid = ParentPid;
    RtlZeroMemory(ev->ImageName, sizeof(ev->ImageName));
    if (ImageFileName != NULL && ImageFileName->Buffer != NULL) {
        ULONG copyLen = ImageFileName->Length;
        if (copyLen > sizeof(ev->ImageName) - sizeof(WCHAR))
            copyLen = sizeof(ev->ImageName) - sizeof(WCHAR);
        RtlCopyMemory(ev->ImageName, ImageFileName->Buffer, copyLen);
    }
    gEventWriteIndex = (gEventWriteIndex + 1) % MAX_EVENTS;
    if (gEventCount < MAX_EVENTS)
        gEventCount++;
    KeReleaseSpinLock(&gEventsLock, oldIrql);
}

VOID ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        ULONG ppid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        DbgPrint("Unified: [CREATE] PID=%lu PPID=%lu Image=%wZ\n",
                 pid, ppid, CreateInfo->ImageFileName);
        LogEvent(TRUE, pid, ppid, CreateInfo->ImageFileName);
    } else {
        DbgPrint("Unified: [EXIT] PID=%lu\n", pid);
        LogEvent(FALSE, pid, 0, NULL);
    }
}

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    PEPROCESS targetProcess;
    ULONG targetPid;
    LONG protectedPid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    protectedPid = InterlockedCompareExchange(&gProtectedPid, 0, 0);
    if (protectedPid == 0)
        return OB_PREOP_SUCCESS;

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);
    if (targetPid != (ULONG)protectedPid)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(ACCESS_MASK)PROCESS_TERMINATE;
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(ACCESS_MASK)PROCESS_TERMINATE;

    return OB_PREOP_SUCCESS;
}

NTSTATUS UnifiedCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS UnifiedDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stackLocation;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    stackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch(stackLocation->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_SET_PROTECTED_PID:
    {
        PULONG inBuf = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        ULONG inLen = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
        if (inBuf == NULL || inLen < sizeof(ULONG)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        InterlockedExchange(&gProtectedPid, (LONG)*inBuf);
        DbgPrint("Unified: PID protege = %lu\n", *inBuf);
        break;
    }

    case IOCTL_GET_EVENTS:
    {
        PMONITOR_EVENT outBuf = (PMONITOR_EVENT)Irp->AssociatedIrp.SystemBuffer;
        ULONG outLen = stackLocation->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG maxEvents = outLen / sizeof(MONITOR_EVENT);
        ULONG toCopy;
        KIRQL oldIrql;

        if (outBuf == NULL || maxEvents == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KeAcquireSpinLock(&gEventsLock, &oldIrql);
        toCopy = (gEventCount < maxEvents) ? gEventCount : maxEvents;
        RtlCopyMemory(outBuf, gEvents, toCopy * sizeof(MONITOR_EVENT));
        KeReleaseSpinLock(&gEventsLock, oldIrql);
        information = toCopy * sizeof(MONITOR_EVENT);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID UnifiedUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    if (gObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(gObRegistrationHandle);
        gObRegistrationHandle = NULL;
    }
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("Unified: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName, symLink, altitude;
    PDEVICE_OBJECT deviceObject = NULL;
    OB_OPERATION_REGISTRATION operationRegistration[1];
    OB_CALLBACK_REGISTRATION callbackRegistration;

    UNREFERENCED_PARAMETER(RegistryPath);
    KeInitializeSpinLock(&gEventsLock);

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = UnifiedCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = UnifiedCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UnifiedDeviceControl;
    DriverObject->DriverUnload = UnifiedUnload;
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Unified: PsSetCreateProcessNotifyRoutineEx echoue 0x%08X\n", status);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
        return status;
    }

    RtlInitUnicodeString(&altitude, L"370000");
    RtlZeroMemory(operationRegistration, sizeof(operationRegistration));
    operationRegistration[0].ObjectType  = PsProcessType;
    operationRegistration[0].Operations  = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = PreOperationCallback;
    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.OperationRegistration = operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration, &gObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("Unified: loaded\n");
    return STATUS_SUCCESS;
}
