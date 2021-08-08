#include "Include.hpp"

struct EntryInitialize
{
	std::uintptr_t mappedImageBase{};
	std::size_t mappedImageSize{};
};

NTSTATUS DriverEntry(EntryInitialize* entryParam)
{
	DebugPrint("Example Driver Mapped [%p] w/ Size [0x%x]", entryParam->mappedImageBase, entryParam->mappedImageSize);

	ExFreePool(reinterpret_cast<void*>(entryParam));

	return STATUS_SUCCESS;
}