#include <ntddk.h>

VOID HelloUnload(_In_ PDRIVER_OBJECT DriverObject)
{
   UNREFERENCED_PARAMETER(DriverObject);
   DbgPrint("Hello: Driver unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(RegPath);

    DbgPrint("Hello: Driver loaded!\n");
    DriverObject->DriverUnload = HelloUnload;
    return STATUS_SUCCESS;
}
