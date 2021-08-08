#pragma once

#include <ntifs.h>
#include <windef.h>

#include <ntimage.h>
#include <cstdint>
#include <cstddef>

#include "Native.hpp"
#include "Mapper.hpp"
#include "Memory.hpp"

#include "Signature Scan.hpp"

#define RelativeAddress(addr, size) ((PVOID*)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))
#define DebugPrint(fmt, ...) DbgPrintEx(0, 0, "[SignedManualMapper] " fmt, ##__VA_ARGS__)