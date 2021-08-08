#pragma once

namespace Mapper
{
	BOOLEAN resolveImports(std::uintptr_t imageBase);
	void resolveRelocations(std::uintptr_t imageBase, std::uintptr_t newBase, std::uintptr_t delta);
}