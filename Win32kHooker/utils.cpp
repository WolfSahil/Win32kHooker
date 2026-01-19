#include "global.h"

PVOID GetModuleBase(const char* moduleName, PULONG moduleSize = nullptr) {
    if (!moduleName) {
        return nullptr;
    }

    ULONG bufferSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformation,
        &bufferSize,
        0,
        &bufferSize
    );

    if (bufferSize == 0) {
        return nullptr;
    }

    auto* moduleInfo = static_cast<SYSTEM_MODULE_INFORMATION*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'w32h')
        );

    if (!moduleInfo) {
        return nullptr;
    }

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        moduleInfo,
        bufferSize,
        nullptr
    );

    PVOID moduleBase = nullptr;

    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < moduleInfo->ulModuleCount; i++) {
            const auto* entry = &moduleInfo->Modules[i];

            if (strstr(entry->ImageName, moduleName)) {
                moduleBase = entry->Base;
                if (moduleSize) {
                    *moduleSize = entry->Size;
                }
                break;
            }
        }
    }

    ExFreePoolWithTag(moduleInfo, 'w32h');
    return moduleBase;
}


PVOID MapModuleFromKnownDll(PCWSTR dllName) {
    if (!dllName) {
        return nullptr;
    }

    constexpr WCHAR kKnownDllsPrefix[] = L"\\KnownDlls\\";
    WCHAR fullPath[MAX_PATH]{};

    wcscpy_s(fullPath, kKnownDllsPrefix);
    wcscat_s(fullPath, dllName);

    UNICODE_STRING uniStr{};
    RtlInitUnicodeString(&uniStr, fullPath);

    OBJECT_ATTRIBUTES objAttr{};
    InitializeObjectAttributes(
        &objAttr,
        &uniStr,
        OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr
    );

    HANDLE hSection = nullptr;
    NTSTATUS status = ZwOpenSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        &objAttr
    );

    if (!NT_SUCCESS(status) || !hSection) {
        return nullptr;
    }

    PVOID moduleBase = nullptr;
    SIZE_T viewSize = 0;

    status = ZwMapViewOfSection(
        hSection,
        reinterpret_cast<HANDLE>(-1),
        &moduleBase,
        0,
        viewSize,
        nullptr,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    ZwClose(hSection);

    if (!NT_SUCCESS(status)) {
        return nullptr;
    }

    return moduleBase;
}

PVOID GetExportAddress(PVOID moduleBase, LPCSTR functionName) {
    if (!moduleBase || !functionName) {
        return nullptr;
    }

    const auto* dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    const SIZE_T moduleBaseAddr = reinterpret_cast<SIZE_T>(moduleBase);
    const SIZE_T peHeaderOffset = static_cast<SIZE_T>(
        *reinterpret_cast<PDWORD>(moduleBaseAddr + 0x3C)
        );

    const SIZE_T optHeaderAddr = moduleBaseAddr + peHeaderOffset + 0x18;
    const WORD magic = *reinterpret_cast<PWORD>(optHeaderAddr);

    SIZE_T dataDirectoryAddr = 0;
    if (magic == 0x10B) { // PE32
        dataDirectoryAddr = optHeaderAddr + 0x60;
    }
    else if (magic == 0x20B) { // PE32+
        dataDirectoryAddr = optHeaderAddr + 0x70;
    }
    else {
        return nullptr;
    }

    const SIZE_T exportRva = static_cast<SIZE_T>(
        *reinterpret_cast<PDWORD>(dataDirectoryAddr)
        );
    const SIZE_T exportBase = moduleBaseAddr + exportRva;

    const DWORD ordinalBase = *reinterpret_cast<PDWORD>(exportBase + 0x10);
    const DWORD numberOfNames = *reinterpret_cast<PDWORD>(exportBase + 0x18);
    const SIZE_T functionsRva = static_cast<SIZE_T>(
        *reinterpret_cast<PDWORD>(exportBase + 0x1C)
        );
    const SIZE_T namesRva = static_cast<SIZE_T>(
        *reinterpret_cast<PDWORD>(exportBase + 0x20)
        );
    const SIZE_T ordinalsRva = static_cast<SIZE_T>(
        *reinterpret_cast<PDWORD>(exportBase + 0x24)
        );

    for (DWORD i = 0; i < numberOfNames; i++) {
        const SIZE_T nameRvaAddr = moduleBaseAddr + namesRva + (static_cast<SIZE_T>(i) * 4);
        const SIZE_T functionNameRva = static_cast<SIZE_T>(
            *reinterpret_cast<PDWORD>(nameRvaAddr)
            );
        const auto* currentName = reinterpret_cast<PCHAR>(moduleBaseAddr + functionNameRva);

        if (strcmp(currentName, functionName) == 0) {
            const SIZE_T ordinalAddr = moduleBaseAddr + ordinalsRva + (static_cast<SIZE_T>(i) * 2);
            const WORD functionOrdinal = *reinterpret_cast<PWORD>(ordinalAddr) +
                static_cast<WORD>(ordinalBase);

            const SIZE_T functionRvaAddr = moduleBaseAddr + functionsRva +
                (static_cast<SIZE_T>(4) * (functionOrdinal - ordinalBase));
            const SIZE_T functionRva = static_cast<SIZE_T>(
                *reinterpret_cast<PDWORD>(functionRvaAddr)
                );

            return reinterpret_cast<PVOID>(moduleBaseAddr + functionRva);
        }
    }

    return nullptr;
}

PVOID GetWin32kSdtAddress() {
    PVOID win32kAddr = GetModuleBase("win32k.sys");
    return GetExportAddress(win32kAddr, "W32pServiceTable");
}

bool GetWin32kSyscallNumber(PCSTR functionName, PDWORD syscallNumber) {
    if (!functionName || !syscallNumber) {
        return false;
    }

    if (_strnicmp(functionName, "Nt", 2)) {
        return false;
    }

    PVOID ntdllBase = MapModuleFromKnownDll(L"win32u.dll");
    if (!ntdllBase) {
        return false;
    }

    PVOID functionAddr = GetExportAddress(ntdllBase, functionName);
    if (!functionAddr) {
        ZwUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), ntdllBase);
        return false;
    }

    // Check for "mov eax, imm32" instruction (B8 XX XX XX XX)
    constexpr UCHAR kMovEaxOpcode = 0xB8;
    constexpr size_t kMovEaxOpcodeOffset = 3;
    constexpr size_t kSyscallNumberOffset = 4;

    const auto* functionBytes = static_cast<PUCHAR>(functionAddr);
    if (functionBytes[kMovEaxOpcodeOffset] == kMovEaxOpcode) {
        *syscallNumber = *reinterpret_cast<PDWORD>(
            reinterpret_cast<SIZE_T>(functionAddr) + kSyscallNumberOffset
            );
        ZwUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), ntdllBase);
        return true;
    }

    ZwUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), ntdllBase);
    return false;
}

PVOID GetWin32kSyscallRoutine(PVOID win32ksdt, LPCSTR syscallName, DWORD syscallNumber) {
    // Validate inputs
    if (syscallName) {
        if (_strnicmp(syscallName, "Nt", 2)) {
            return nullptr;
        }

        // If name provided but no number, resolve number
        if (!syscallNumber) {
            if (!GetWin32kSyscallNumber(syscallName, &syscallNumber)) {
                return nullptr;
            }
        }
    }

    LONG routineOffset = *(PLONG)((DWORD64)win32ksdt + ((syscallNumber & 0xFFF) * 4));

    return (PVOID)((LONGLONG)win32ksdt + ((LONGLONG)((DWORD)routineOffset >> 4) | 0xFFFFFFFFF0000000));
}

bool PatternCheck(const char* data, const char* pattern, const char* mask) {
    size_t length = strlen(mask);

    for (size_t i = 0; i < length; i++) {
        if (mask[i] == '?') {
            continue;
        }
        if (data[i] != pattern[i]) {
            return false;
        }
    }

    return true;
}

PVOID FindPattern(
    PVOID address,
    SIZE_T size,
    const char* pattern,
    const char* mask
) {
    if (!address || !pattern || !mask) {
        return nullptr;
    }

    SIZE_T maskLength = strlen(mask);
    if (size < maskLength) {
        return nullptr;
    }

    size -= maskLength;

    for (SIZE_T i = 0; i < size; i++) {
        if (PatternCheck((const char*)((ULONG_PTR)address + i), pattern, mask)) {
            return (PVOID)((ULONG_PTR)address + i);
        }
    }

    return nullptr;
}

PEPROCESS FindGUIProcess() {
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    PEPROCESS hProcess = NULL;

    // 1. Initial size estimate (e.g., 64KB). 
    // It will likely be too small, but the loop handles re-allocation.
    bufferSize = 64 * 1024;

    while (TRUE) {
        // Allocate from PagedPool (Processes info is safe in PagedPool at PASSIVE_LEVEL)
        buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'Proc');
        if (!buffer) {
            return NULL;
        }

        // Query the process list
        ULONG requiredSize = 0;
        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &requiredSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            // Buffer too small, free and try again with the required size + margin
            ExFreePool(buffer);
            bufferSize = requiredSize + (4 * 1024); // Add 4k padding for safety as processes change rapidly
        }
        else {
            // Success or fatal error
            break;
        }
    }

    if (!NT_SUCCESS(status)) {
        if (buffer) ExFreePool(buffer);
        return NULL;
    }

    // 2. Iterate the list
    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    UNICODE_STRING targetName;
    RtlInitUnicodeString(&targetName, L"winlogon.exe");

    while (TRUE) {
        // Check if ImageName matches "explorer.exe"
        // Note: ImageName can be NULL for System Idle Process
        if (pInfo->ImageName.Buffer && RtlEqualUnicodeString(&pInfo->ImageName, &targetName, TRUE)) {

            // Found it! Get the PEPROCESS from the PID.
            // PsLookupProcessByProcessId increments the reference count automatically.
            status = PsLookupProcessByProcessId(pInfo->UniqueProcessId, &hProcess);
            if (NT_SUCCESS(status)) {
                // Break the loop, we have our object.
                // If you want a specific session's explorer, check pInfo->SessionId here.
                break;
            }
        }

        // Move to next entry
        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
    }

    // 3. Cleanup
    ExFreePool(buffer);

    return hProcess; // Returns NULL if not found, or a valid PEPROCESS pointer
}