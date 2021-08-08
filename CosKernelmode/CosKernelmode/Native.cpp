#include "Include.hpp"

namespace Native
{
	bool safeCopyMemory(PVOID dest, PVOID src, SIZE_T size)
	{
		SIZE_T returnSize = 0;
		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
			return TRUE;
		}

		return FALSE;
	}

	NTSTATUS getKernelModuleByName(const char* moduleName, std::uintptr_t* moduleStart, std::size_t* moduleSize)
	{
		if (!moduleStart || !moduleSize)
			return STATUS_INVALID_PARAMETER;

		std::size_t size{};
		ZwQuerySystemInformation(0xB, nullptr, size, reinterpret_cast<PULONG>(&size));

		const auto listHeader = ExAllocatePool(NonPagedPool, size);
		if (!listHeader)
			return STATUS_MEMORY_NOT_ALLOCATED;

		if (const auto status = ZwQuerySystemInformation(0xB, listHeader, size, reinterpret_cast<PULONG>(&size)))
			return status;

		auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;
		for (std::size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
		{
			const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
			if (!strcmp(moduleName, currentModuleName))
			{
				*moduleStart = reinterpret_cast<std::uintptr_t>(currentModule->ImageBase);
				*moduleSize = currentModule->ImageSize;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}
}