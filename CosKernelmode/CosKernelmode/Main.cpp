#include "Include.hpp"

std::uintptr_t(NTAPI* EnumerateDebuggingDevicesOriginal)(std::uintptr_t, std::uintptr_t*);
std::uintptr_t hookAddress{};

struct EntryInitialize
{
	std::uintptr_t mappedImageBase{};
	std::size_t mappedImageSize{};
};

struct HookStruct
{
	std::size_t rawDataSize{};
	std::uintptr_t rawDataAddress{};
};

using EntryFuncCall = NTSTATUS(__stdcall*) (EntryInitialize*);

std::uintptr_t NTAPI EnumerateDebuggingDevicesHook(std::uintptr_t data, std::uintptr_t* status)
{
	if (ExGetPreviousMode() != UserMode || !data) 
	{
		return EnumerateDebuggingDevicesOriginal(data, status);
	}

	HookStruct requestStruct = { 0 };
	if (!Native::safeCopyMemory(&requestStruct, reinterpret_cast<void*>(data), sizeof(requestStruct)) || !requestStruct.rawDataSize || !requestStruct.rawDataAddress)
	{
		return EnumerateDebuggingDevicesOriginal(data, status);
	}

	std::uintptr_t driverBase = reinterpret_cast<std::uintptr_t>(ExAllocatePool(NonPagedPool, requestStruct.rawDataSize));
	if (!driverBase) return STATUS_UNSUCCESSFUL;

	memcpy(reinterpret_cast<void*>(driverBase), reinterpret_cast<void*>(requestStruct.rawDataAddress), requestStruct.rawDataSize);

	Mapper::resolveImports(driverBase);

	const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(driverBase);
	const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(driverBase + dosHeaders->e_lfanew);

	const PIMAGE_SECTION_HEADER currentImageSection = IMAGE_FIRST_SECTION(ntHeaders);

	// Allocate Memory for Mapped Driver w/o HEADERS Size - PAGE_SIZE (Mapping Without PE Header (First Page))
	const auto driverAllocationBase = reinterpret_cast<std::uintptr_t>(ExAllocatePool(NonPagedPool, ntHeaders->OptionalHeader.SizeOfImage)) - PAGE_SIZE;
	if (!driverAllocationBase)
	{
		*status = STATUS_UNSUCCESSFUL;
		return 0;
	}

	Memory::cleanBigPoolAllocation(driverAllocationBase + PAGE_SIZE);

	for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		auto sectionAddress = reinterpret_cast<void*>(driverAllocationBase + currentImageSection[i].VirtualAddress);

		memcpy(sectionAddress, reinterpret_cast<void*>(driverBase + currentImageSection[i].PointerToRawData), currentImageSection[i].SizeOfRawData);
	}

	Mapper::resolveRelocations(driverBase, driverAllocationBase, driverAllocationBase - ntHeaders->OptionalHeader.ImageBase);

	ExFreePool(reinterpret_cast<void*>(driverBase));

	const auto entryParams = reinterpret_cast<EntryInitialize*>(ExAllocatePool(NonPagedPool, sizeof(EntryInitialize)));
	if (!entryParams)
	{
		*status = STATUS_UNSUCCESSFUL;
		return 0;
	}

	entryParams->mappedImageBase = driverAllocationBase;
	entryParams->mappedImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	EntryFuncCall mappedEntryPoint = reinterpret_cast<EntryFuncCall>(driverAllocationBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

	*status = mappedEntryPoint(entryParams);

	return 0;
}

void DriverUnload(PDRIVER_OBJECT driverObject) 
{
	reinterpret_cast<std::uintptr_t>(InterlockedExchangePointer(RelativeAddress(hookAddress, 7), (PVOID)EnumerateDebuggingDevicesOriginal));

	reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->BaseDllName.Length = 0;

	Memory::cleanPiddbCache(driverObject);
}

NTSTATUS DriverEntry(const PDRIVER_OBJECT driverObject, const PUNICODE_STRING registryPath)
{
	driverObject->DriverUnload = DriverUnload;

	std::uintptr_t ntoskrnlBase;
	std::uintptr_t ntoskrnlSize;

	Native::getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize);
	if (!ntoskrnlBase)
	{
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	hookAddress = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlBase), ntoskrnlSize, "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40", "xxx????x????xxxxxx");
	if (!hookAddress)
	{
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*reinterpret_cast<std::uintptr_t*>(&EnumerateDebuggingDevicesOriginal) = reinterpret_cast<std::uintptr_t>(InterlockedExchangePointer(RelativeAddress(hookAddress, 7), (PVOID)EnumerateDebuggingDevicesHook));

	return STATUS_SUCCESS;
}