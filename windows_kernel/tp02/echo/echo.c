#include <ntddk.h>
#include "echo.h"

#define DEVICE_NAME  L"\\Device\\EchoDriver"
#define SYMLINK_NAME L"\\??\\EchoDriverLink"

NTSTATUS EchoCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
   UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS EchoDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stackLocation;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    stackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch(stackLocation->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_ECHO:
    {
        PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
        ULONG inputLength = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = stackLocation->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG copyLength = (inputLength < outputLength) ? inputLength : outputLength;

        if (systemBuffer == NULL || copyLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DbgPrint("Echo: recu %lu octets : %.*s\n", inputLength, (int)inputLength, (PCHAR)systemBuffer);
        RtlCopyMemory(systemBuffer, systemBuffer, copyLength);
        information = copyLength;
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

VOID EchoUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("Echo: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLink;
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

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = EchoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = EchoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EchoDeviceControl;
    DriverObject->DriverUnload = EchoUnload;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("Echo: loaded\n");
    return STATUS_SUCCESS;
}
