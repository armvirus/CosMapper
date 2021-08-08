#include "Include.hpp"

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		list;
	UNICODE_STRING	driverName;
	ULONG			driverStamp;
	NTSTATUS		loadStatus;
};

typedef struct _POOL_TRACKER_BIG_PAGES
{
	PVOID Va;
	ULONG Key;
	ULONG PoolType;
	ULONG NumberOfBytes;
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

namespace Memory
{
	NTSTATUS cleanBigPoolAllocation(std::uintptr_t allocationAddress)
	{
		std::uintptr_t ntoskrnlBase{};
		std::size_t ntoskrnlSize{};

		Native::getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize);

		std::uintptr_t exProtectPoolExCallInstructionsAddress = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlBase), ntoskrnlSize, "\xE8\x00\x00\x00\x00\x83\x67\x0C\x00", "x????xxxx");

		if (!exProtectPoolExCallInstructionsAddress)
			return STATUS_NOT_FOUND;

		void* ExProtectPoolExAddress = reinterpret_cast<void*>(exProtectPoolExCallInstructionsAddress + *reinterpret_cast<int32_t*>(exProtectPoolExCallInstructionsAddress + 1) + 5);

		if (!ExProtectPoolExAddress)
			return STATUS_NOT_FOUND;

		uintptr_t PoolBigPageTableInstructionAddress = ((ULONG64)ExProtectPoolExAddress + 0x95);
		uint64_t pPoolBigPageTable = (uint64_t)(PoolBigPageTableInstructionAddress + *reinterpret_cast<int32_t*>(PoolBigPageTableInstructionAddress + 3) + 7);

		uintptr_t PoolBigPageTableSizeInstructionAddress = ((ULONG64)ExProtectPoolExAddress + 0x8E);
		uint64_t pPoolBigPageTableSize = (uint64_t)(PoolBigPageTableSizeInstructionAddress + *reinterpret_cast<int32_t*>(PoolBigPageTableSizeInstructionAddress + 3) + 7);

		if (!pPoolBigPageTableSize || !pPoolBigPageTable)
			return STATUS_NOT_FOUND;

		PPOOL_TRACKER_BIG_PAGES PoolBigPageTable = 0;
		RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);

		SIZE_T PoolBigPageTableSize = 0;
		RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);

		if (!PoolBigPageTableSize || !PoolBigPageTable)
			return STATUS_NOT_FOUND;

		for (int i = 0; i < PoolBigPageTableSize; i++)
		{
			if (PoolBigPageTable[i].Va == reinterpret_cast<void*>(allocationAddress) || PoolBigPageTable[i].Va == reinterpret_cast<void*>(allocationAddress + 0x1))
			{
				PoolBigPageTable[i].Va = reinterpret_cast<void*>(0x1);
				PoolBigPageTable[i].NumberOfBytes = 0x0;

				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	NTSTATUS cleanPiddbCache(PDRIVER_OBJECT driverObject)
	{
		std::uintptr_t ntoskrnlBase{};
		std::size_t ntoskrnlSize{};

		Native::getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize);

		std::uintptr_t piddbLockAddress = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlBase), ntoskrnlSize, "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C\x24", "xxx????x????xxxx");

		if(!piddbLockAddress)
			return STATUS_UNSUCCESSFUL;

		piddbLockAddress += 3;
		piddbLockAddress += *reinterpret_cast<std::int32_t*>(piddbLockAddress) + sizeof(std::int32_t);

		std::uintptr_t piddbTableAddress = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlBase), ntoskrnlSize, "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x1D\x00\x00\x00\x00\x48\x85\xC0\x0F", "xxx????x????xxx????xxxx");

		if (!piddbTableAddress)
			return STATUS_UNSUCCESSFUL;

		piddbTableAddress += 3;
		piddbTableAddress += *reinterpret_cast<std::int32_t*>(piddbTableAddress) + sizeof(std::int32_t);

		PiDDBCacheEntry cacheEntry;
		RtlInitUnicodeString(&cacheEntry.driverName, reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->BaseDllName.Buffer);

		if (!ExAcquireResourceExclusiveLite(reinterpret_cast<PERESOURCE>(piddbLockAddress), true))
			return STATUS_UNSUCCESSFUL;

		PiDDBCacheEntry* entryPointer =
			reinterpret_cast<PiDDBCacheEntry*>(RtlLookupElementGenericTableAvl(
				reinterpret_cast<PRTL_AVL_TABLE>(piddbTableAddress),
				reinterpret_cast<void*>(&cacheEntry)
			));

		if (entryPointer)
		{
			PLIST_ENTRY NextEntry = entryPointer->list.Flink;
			PLIST_ENTRY PrevEntry = entryPointer->list.Blink;

			PrevEntry->Flink = entryPointer->list.Flink;
			NextEntry->Blink = entryPointer->list.Blink;

			entryPointer->list.Blink = PrevEntry;
			entryPointer->list.Flink = NextEntry;

			RtlDeleteElementGenericTableAvl(reinterpret_cast<PRTL_AVL_TABLE>(piddbTableAddress), entryPointer);
		}
		else
			return STATUS_UNSUCCESSFUL;

		ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(piddbLockAddress));

		return STATUS_SUCCESS;
	}
}