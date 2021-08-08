# CosMapper
Loads a signed kernel driver which allows you to map any driver to kernel mode without any traces of the signed / mapped driver.

The usermode program loads the signed driver which then does a .data hook on a ntoskrnl function to transfer the mapped driver buffer to kernel, after the driver is mapped the signed driver is unloaded and all traces including MmUnloadedList PiddbCache and BigPoolAllocation are cleaned aswell as no header is mapped and no empty bytes for the header of the driver to minimize detection.

Your driver needs an entry like the example driver:

```
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
```
The current example passes a structure with the image base and size of the mapped driver but it can be modified to your own liking.
