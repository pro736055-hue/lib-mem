#pragma once
#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>

namespace MemoryLib {
    namespace Imps {
        enum ThreadAccess {
            TERMINATE = 1,
            SUSPEND_RESUME = 2,
            GET_CONTEXT = 8,
            SET_CONTEXT = 16,
            SET_INFORMATION = 32,
            QUERY_INFORMATION = 64,
            SET_THREAD_TOKEN = 128,
            IMPERSONATE = 256,
            DIRECT_IMPERSONATION = 512
        };
    }
}

