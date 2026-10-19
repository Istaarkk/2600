#include <ntddk.h>

#define DEVICE_NAME  L"\\Device\\ProtectorDriver"
#define SYMLINK_NAME L"\\??\\ProtectorDriverLink"

#define IOCTL_SET_PROTECTED_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB00, METHOD_BUFFERED, FILE_ANY_ACCESS)

volatile LONG gProtectedPid = 0;
PVOID gRegistrationHandle = NULL;

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

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        DbgPrint("Protector: HANDLE_CREATE sur PID %lu droits=0x%08X caller=%lu\n",
                 targetPid,
                 OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess
            &= ~(ACCESS_MASK)PROCESS_TERMINATE;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
            &= ~(ACCESS_MASK)PROCESS_TERMINATE;
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS ProtectorCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS ProtectorDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stackLocation;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);
    stackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_SET_PROTECTED_PID) {
        PULONG inBuf = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        ULONG inLen = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
        if (inBuf == NULL || inLen < sizeof(ULONG)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            InterlockedExchange(&gProtectedPid, (LONG)*inBuf);
            DbgPrint("Protector: PID protege mis a jour : %lu\n", *inBuf);
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID ProtectorUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;

    if (gRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(gRegistrationHandle);
        gRegistrationHandle = NULL;
    }

    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("Protector: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName, symLink, altitude;
    PDEVICE_OBJECT deviceObject = NULL;
    OB_OPERATION_REGISTRATION operationRegistration[1];
    OB_CALLBACK_REGISTRATION callbackRegistration;

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

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = ProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = ProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProtectorDeviceControl;
    DriverObject->DriverUnload = ProtectorUnload;
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&altitude, L"370000");

    RtlZeroMemory(operationRegistration, sizeof(operationRegistration));
    operationRegistration[0].ObjectType   = PsProcessType;
    operationRegistration[0].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = PreOperationCallback;
    operationRegistration[0].PostOperation = NULL;

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = NULL;
    callbackRegistration.OperationRegistration = operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration, &gRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Protector: ObRegisterCallbacks echoue 0x%08X\n", status);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("Protector: loaded, en attente d'un PID via IOCTL\n");
    return STATUS_SUCCESS;
}
