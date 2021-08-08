#pragma once

namespace Memory
{
	NTSTATUS cleanPiddbCache(PDRIVER_OBJECT driverObject);
	NTSTATUS cleanBigPoolAllocation(std::uintptr_t allocationAddress);
}