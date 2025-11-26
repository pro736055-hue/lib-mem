#pragma once
#include <windows.h>

namespace MemoryLib {
    struct MemoryRegionResult {
        DWORD_PTR CurrentBaseAddress;
        SIZE_T RegionSize;
        DWORD_PTR RegionBase;
    };
}

