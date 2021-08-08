#include "Include.hpp"

//
// Scan for a memory pattern
//
std::uintptr_t Scanner::scanPattern(std::uint8_t *base, const std::size_t size, char *pattern, char *mask) 
{
    const auto patternSize = strlen(mask);

    for (std::size_t i = {}; i < size - patternSize; i++)
    {
        for (std::size_t j = {}; j < patternSize; j++)
        {
            if (mask[j] != '?' && *reinterpret_cast<std::uint8_t*>(base + i + j) != static_cast<std::uint8_t>(pattern[j]))
                break;

	        if (j == patternSize - 1)
		        return reinterpret_cast<std::uintptr_t>(base) + i;
        }
    }

    return {};
}

NTSTATUS Scanner::getImageSectionByName(std::uintptr_t imageBase, const char* sectionName, std::uintptr_t* startOut, std::size_t* sizeOut)
{
	if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
		return STATUS_NOT_FOUND;

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(
		imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
	const auto sectionCount = ntHeader->FileHeader.NumberOfSections;

	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (std::size_t i{}; i < sectionCount; ++i, ++sectionHeader) {
		if (strstr(reinterpret_cast<const char*>(sectionHeader->Name), sectionName)) {
			if (sizeOut)
				*sizeOut = sectionHeader->Misc.VirtualSize;
			if (startOut)
				*startOut = imageBase + sectionHeader->VirtualAddress;
		}
	}

	return STATUS_SUCCESS;
}