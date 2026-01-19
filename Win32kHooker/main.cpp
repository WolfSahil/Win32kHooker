#include "hooker.h"

extern "C" VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    RemoveHooker();
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

    InitializeHooker();
	return STATUS_UNSUCCESSFUL;
}