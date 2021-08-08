#pragma once

namespace Scanner 
{
	std::uintptr_t scanPattern(std::uint8_t *base, const std::size_t size, char *pattern, char *mask);
	NTSTATUS getImageSectionByName(std::uintptr_t imageBase, const char* sectionName, std::uintptr_t* startOut, std::size_t* sizeOut);
	std::uintptr_t getImageSectionByName(std::uintptr_t imageBase, const char* sectionName, std::size_t* sizeOut);
}