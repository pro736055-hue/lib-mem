#pragma once
#include <windows.h>
#include <psapi.h>

namespace MemoryLib {
    class Proc {
    public:
        HANDLE Handle = nullptr;
        bool Is64Bit = false;
        MODULEINFO MainModule = {};

        Proc() = default;
        ~Proc() {
            if (Handle != nullptr) {
                CloseHandle(Handle);
                Handle = nullptr;
            }
        }
    };
}

