#include <windows.h>
#include <stdio.h>
#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <fstream>

#include "util.hpp"
#include "loadup.hpp"
#include "mapper_resource.hpp"

struct HookStruct
{
	std::size_t rawDataSize{};
	std::uintptr_t rawDataAddress{};
};