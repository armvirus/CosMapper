#pragma once

#include <ntifs.h>
#include <windef.h>

#include <cstdint>
#include <cstddef>

#define DebugPrint(fmt, ...) DbgPrintEx(0, 0, "[ExampleMappedDriver] " fmt, ##__VA_ARGS__)